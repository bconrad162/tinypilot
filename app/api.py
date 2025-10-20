import logging
import threading
import time

import flask

import auth
import db.settings
import db.users
import debug_logs
import env
import execute
import js_to_hid
import hostname
import json_response
import local_system
import network
import request_parsers.create_user
import request_parsers.credentials
import request_parsers.delete_user
import request_parsers.errors
import request_parsers.hostname
import request_parsers.keystroke
import request_parsers.mouse_event
import request_parsers.network
import request_parsers.paste
import request_parsers.macro
import request_parsers.requires_https
import request_parsers.video_settings
import session
import update.launcher
import update.settings
import update.status
import version
import video_service
from hid import keyboard as fake_keyboard
from hid import mouse as fake_mouse
from hid import write as hid_write

api_blueprint = flask.Blueprint('api', __name__, url_prefix='/api')

logger = logging.getLogger(__name__)

_MAX_SIMULTANEOUS_HID_KEYS = 6
_pressed_keystrokes = {}
_pressed_lock = threading.Lock()
_mouse_buttons_pressed = 0
_mouse_lock = threading.Lock()


class Error(Exception):
    pass


class NotAuthenticatedError(Error):
    pass


class UnableToDeleteCurrentUserError(Error):
    code = 'UNABLE_TO_DELETE_CURRENT_USER'


class TooManySimultaneousKeysError(Error):
    pass


def _required_auth_level_decorator(required_auth_level):

    def decorator(view_func):
        view_func.required_auth_level = required_auth_level
        return view_func

    return decorator


def required_auth(satisfies_role):
    """Decorator to specify the minimum required auth level for an endpoint.

    See `session.is_auth_valid` for details on the auth rules.

    Args:
        satisfies_role: A role value that is at least required to access this
            endpoint.
    """
    return _required_auth_level_decorator(satisfies_role)


def no_auth_required():
    """Decorator to exempt an endpoint from any auth check altogether.

    The endpoint will be publicly accessible by anyone, regardless of the
    system’s current authentication requirements.
    """
    return _required_auth_level_decorator(None)


@api_blueprint.before_request
def enforce_auth():
    """Enforce client authentication checks by default."""
    view_func = flask.current_app.view_functions[flask.request.endpoint]

    try:
        required_auth_level = getattr(view_func, 'required_auth_level')
    except AttributeError as e:
        # This is an internal check for us that should help to enforce putting
        # an auth-related annotation on every endpoint. This error is not
        # supposed to ever make it past the development stage.
        raise Error(f'CODE ERROR: Missing auth annotation on '
                    f'{flask.request.endpoint} endpoint') from e

    # No authentication/authorization is required for this endpoint. Every
    # visitor (even with invalid session) can access this endpoint.
    if required_auth_level is None:
        return None

    # Check whether the current session satisfies the required role.
    if not session.is_auth_valid(required_auth_level):
        return json_response.error(NotAuthenticatedError('Not authorized')), 401

    return None


@api_blueprint.route('/user', methods=['POST'])
@required_auth(auth.Role.ADMIN)
def user_post():
    """Adds a new user to the system.

    Returns:
        On success, a JSON data structure with a property "username" (str).
        Returns error object on failure.
    """
    try:
        username, password, role = request_parsers.create_user.parse(
            flask.request)
    except request_parsers.errors.Error as e:
        return json_response.error(e), 400

    try:
        auth.register(username, password, role)
    except db.users.UserAlreadyExistsError as e:
        return json_response.error(e), 409
    if len(auth.get_all_accounts()) == 1:
        session.login(username)
    return json_response.success({'username': username})


@api_blueprint.route('/user/password', methods=['PUT'])
@required_auth(auth.Role.ADMIN)
def user_password_put():
    """Updates an existing user's password.

    Returns:
        Empty response on success, error object otherwise.
    """
    try:
        username, password = request_parsers.credentials.parse_credentials(
            flask.request)
    except request_parsers.errors.Error as e:
        return json_response.error(e), 400

    try:
        auth.change_password(username, password)
    except db.users.UserDoesNotExistError as e:
        return json_response.error(e), 404

    if username == session.get_username():
        # If the currently logged-in user's credentials have changed, refresh
        # their session.
        session.login(username)

    return json_response.success()


@api_blueprint.route('/user', methods=['DELETE'])
@required_auth(auth.Role.ADMIN)
def user_delete():
    """Removes a user from the system.

    Returns:
        On success, a JSON data structure with a property "username" (str).
        Returns error object on failure.
    """
    try:
        username = request_parsers.delete_user.parse_delete(flask.request)
    except request_parsers.errors.Error as e:
        return json_response.error(e), 400

    if username == session.get_username() and len(auth.get_all_accounts()) > 1:
        return json_response.error(
            UnableToDeleteCurrentUserError(
                'Unable to remove currently logged-in user while other users'
                ' exist')), 409

    try:
        auth.delete_account(username)
    except db.users.UserDoesNotExistError as e:
        return json_response.error(e), 404

    if username == session.get_username():
        session.logout()

    return json_response.success({'username': username})


@api_blueprint.route('/auth', methods=['GET'])
@required_auth(auth.Role.OPERATOR)
def auth_get():
    """Checks whether the user is authenticated.

    This is an internal endpoint queried by our NGINX proxy to check for the
    authentication state of the backend.
    """
    return json_response.success()


@api_blueprint.route('/auth', methods=['POST'])
@no_auth_required()
def auth_post():
    """Authenticates a user with username and password.

    Returns:
        Empty response on success, error object otherwise.
    """
    logger.info_sensitive(
        'Login request from IP %s',
        flask.request.headers.get('X-Forwarded-For', flask.request.remote_addr))
    try:
        username, password = request_parsers.credentials.parse_credentials(
            flask.request)
    except request_parsers.errors.Error as e:
        return json_response.error(e), 400
    if auth.can_authenticate(username, password):
        session.login(username)
        return json_response.success()
    return json_response.error(
        NotAuthenticatedError('Invalid username and password')), 401


@api_blueprint.route('/logout', methods=['POST'])
@no_auth_required()
def logout_post():
    """Logs out the current user and clears the session.

    Returns:
        Empty response on success, error object otherwise.
    """
    session.logout()
    return json_response.success()


@api_blueprint.route('/debugLogs', methods=['GET'])
@required_auth(auth.Role.ADMIN)
def debug_logs_get():
    """Returns the TinyPilot debug log as a plaintext HTTP response.

    Returns:
        A text/plain response with the content of the logs in the response body.
    """
    try:
        return flask.Response(debug_logs.collect(), mimetype='text/plain')
    except debug_logs.Error as e:
        return flask.Response(f'Failed to retrieve debug logs: {e}', status=500)


@api_blueprint.route('/shutdown', methods=['POST'])
@required_auth(auth.Role.ADMIN)
def shutdown_post():
    """Triggers shutdown of the system.

    Returns:
        Empty response on success, error object otherwise.
    """
    try:
        local_system.shutdown()
        return json_response.success()
    except local_system.Error as e:
        return json_response.error(e), 500


@api_blueprint.route('/restart', methods=['POST'])
@required_auth(auth.Role.ADMIN)
def restart_post():
    """Triggers restart of the system.

    Returns:
        Empty response on success, error object otherwise.
    """
    try:
        local_system.restart()
        return json_response.success()
    except local_system.Error as e:
        return json_response.error(e), 500


@api_blueprint.route('/update', methods=['GET'])
@required_auth(auth.Role.ADMIN)
def update_get():
    """Fetches the state of the latest update job.

    Returns:
        On success, a JSON data structure with the following properties:
        status: str describing the status of the job. Can be one of
                ["NOT_RUNNING", "DONE", "IN_PROGRESS"].
        updateError: str of the error that occurred while updating. If no error
                     occurred, then this will be null.

        Example:
        {
            "status": "NOT_RUNNING",
            "updateError": null
        }
    """
    status, error = update.status.get()
    return json_response.success({'status': str(status), 'updateError': error})


@api_blueprint.route('/update', methods=['PUT'])
@required_auth(auth.Role.ADMIN)
def update_put():
    """Initiates job to update TinyPilot to the latest version available.

    This endpoint asynchronously starts a job to update TinyPilot to the latest
    version.  API clients can then query the status of the job with GET
    /api/update to see the status of the update.

    Returns:
        Empty response on success, error object otherwise.
    """
    try:
        update.launcher.start_async()
    except update.launcher.AlreadyInProgressError:
        # If an update is already in progress, treat it as success.
        pass
    except update.launcher.Error as e:
        return json_response.error(e), 500
    return json_response.success()


@api_blueprint.route('/users', methods=['GET'])
@required_auth(auth.Role.ADMIN)
def users_get():
    """Lists all known users and indicates the currently logged-in user.

    Returns:
        On success, a JSON data structure with the following properties:
        users: array of objects containing usernames and roles (as strings).
        currentUsername: The username (as string) of the currently logged-in
            user or null if not logged in.

        Example:
        {
            "users": [{
                "username": "little-hamster",
                "role": "ADMIN"
            }],
            "currentUsername": "little-hamster"
        }

        Returns error object on failure.
    """
    return json_response.success({
        'users': [{
            'username': u.username,
            'role': u.role.name,
        } for u in auth.get_all_accounts()],
        'currentUsername': session.get_username(),
    })


@api_blueprint.route('/users', methods=['DELETE'])
@required_auth(auth.Role.ADMIN)
def users_delete():
    """Removes all users from the system.

    Returns:
        Empty response on success, error object otherwise.
    """
    auth.delete_all_accounts()
    session.logout()
    return json_response.success()


@api_blueprint.route('/version', methods=['GET'])
@required_auth(auth.Role.OPERATOR)
def version_get():
    """Retrieves the current installed version of TinyPilot.

    Returns:
        On success, a JSON data structure with the following properties:
        version: str.

        Example:
        {
            "version": "1.2.3-16+7a6c812",
        }

        Returns error object on failure.
    """
    try:
        return json_response.success({'version': version.local_version()})
    except version.Error as e:
        return json_response.error(e), 500


@api_blueprint.route('/latestRelease', methods=['GET'])
@required_auth(auth.Role.ADMIN)
def latest_release_get():
    """Retrieves the latest version of TinyPilot.

    Returns:
        On success, a JSON data structure with the following properties:
        version: str.
        kind: str.
        data: object (of kind-specific structure), or null.

        Example:
        {
            "version": "1.2.3-16+7a6c812",
            "kind": "automatic",
            "data": null
        }

        Returns error object on failure.
    """
    try:
        update_info = version.latest_version()
    except version.Error as e:
        return json_response.error(e), 500

    return json_response.success({
        'version': update_info.version,
        'kind': update_info.kind,
        'data': update_info.data,
    })


@api_blueprint.route('/hostname', methods=['GET'])
@required_auth(auth.Role.ADMIN)
def hostname_get():
    """Determines the hostname of the machine.

    Returns:
        On success, a JSON data structure with the following properties:
        hostname: string.

        Example:
        {
            "hostname": "tinypilot"
        }

        Returns an error object on failure.
    """
    try:
        return json_response.success({'hostname': hostname.determine()})
    except hostname.Error as e:
        return json_response.error(e), 500


@api_blueprint.route('/hostname', methods=['PUT'])
@required_auth(auth.Role.ADMIN)
def hostname_set():
    """Changes the machine’s hostname.

    Expects a JSON data structure in the request body that contains the
    new hostname as string. Example:
    {
        "hostname": "grandpilot"
    }

    Returns:
        Empty response on success, error object otherwise.
    """
    try:
        new_hostname = request_parsers.hostname.parse_hostname(flask.request)
        hostname.change(new_hostname)
        return json_response.success()
    except request_parsers.errors.Error as e:
        return json_response.error(e), 400
    except hostname.Error as e:
        return json_response.error(e), 500


@api_blueprint.route('/network/status', methods=['GET'])
@required_auth(auth.Role.ADMIN)
def network_status():
    """Returns the current status of the available network interfaces.

    Returns:
        On success, a JSON data structure with the following:
        interfaces: array of objects, where each object represents a network
            interface with the following properties:
            name: string
            isConnected: boolean
            ipAddress: string or null
            macAddress: string or null

        Example:
        {
            "interfaces": [
                {
                    "name": "eth0",
                    "isConnected": true,
                    "ipAddress": "192.168.2.41",
                    "macAddress": "e4-5f-01-98-65-03"
                },
                {
                    "name": "wlan0",
                    "isConnected": false,
                    "ipAddress": null,
                    "macAddress": null
                }
            ]
        }
    """
    # In dev mode, return dummy data because attempting to read the actual
    # settings will fail in most non-Raspberry Pi OS environments.
    if flask.current_app.debug:
        return json_response.success({
            'interfaces': [
                {
                    'name': 'eth0',
                    'isConnected': True,
                    'ipAddress': '192.168.2.41',
                    'macAddress': 'e4-5f-01-98-65-03',
                },
                {
                    'name': 'wlan0',
                    'isConnected': False,
                    'ipAddress': None,
                    'macAddress': None,
                },
            ],
        })
    network_interfaces = network.determine_network_status()
    return json_response.success({
        'interfaces': [{
            'name': interface.name,
            'isConnected': interface.is_connected,
            'ipAddress': interface.ip_address,
            'macAddress': interface.mac_address,
        } for interface in network_interfaces]
    })


@api_blueprint.route('/network/settings/wifi', methods=['GET'])
@required_auth(auth.Role.ADMIN)
def network_wifi_get():
    """Returns the current WiFi settings, if present.

    Returns:
        On success, a JSON data structure with the following properties:
        countryCode: string.
        ssid: string.

        Example:
        {
            "countryCode": "US",
            "ssid": "my-network"
        }

        Returns an error object on failure.
    """
    wifi_settings = network.determine_wifi_settings()
    return json_response.success({
        'countryCode': wifi_settings.country_code,
        'ssid': wifi_settings.ssid,
    })


@api_blueprint.route('/network/settings/wifi', methods=['PUT'])
@required_auth(auth.Role.ADMIN)
def network_wifi_enable():
    """Enables a wireless network connection.

    Expects a JSON data structure in the request body that contains a country
    code, an SSID, and optionally a password; all as strings. Example:
    {
        "countryCode": "US",
        "ssid": "my-network",
        "psk": "sup3r-s3cr3t!"
    }

    Returns:
        Empty response on success, error object otherwise.
    """
    try:
        wifi_settings = request_parsers.network.parse_wifi_settings(
            flask.request)
        network.enable_wifi(wifi_settings)
        return json_response.success()
    except request_parsers.errors.Error as e:
        return json_response.error(e), 400
    except network.Error as e:
        return json_response.error(e), 500


@api_blueprint.route('/network/settings/wifi', methods=['DELETE'])
@required_auth(auth.Role.ADMIN)
def network_wifi_disable():
    """Disables the WiFi network connection.

    Returns:
        Empty response on success, error object otherwise.
    """
    try:
        network.disable_wifi()
        return json_response.success()
    except network.Error as e:
        return json_response.error(e), 500


@api_blueprint.route('/status', methods=['GET'])
@no_auth_required()
def status_get():
    """Checks the status of TinyPilot.

    This endpoint may be called from all locations, so there is no restriction
    in regards to CORS.

    Returns:
        Empty response, which implies the server is up and running.
    """
    response = json_response.success()
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response


@api_blueprint.route('/settings/requiresHttps', methods=['GET'])
@required_auth(auth.Role.ADMIN)
def settings_requires_https_get():
    """Returns whether the server requires the client to connect via HTTPS.

    Note that the server itself doesn’t handle TLS currently. It only checks how
    the client has connected to the upstream proxy server.

    Returns:
        A JSON data structure with the following properties:
        requiresHttps: bool.

        Example:
        {
            "requiresHttps": true
        }
    """
    return json_response.success(
        {'requiresHttps': db.settings.Settings().requires_https()})


@api_blueprint.route('/settings/requiresHttps', methods=['PUT'])
@required_auth(auth.Role.ADMIN)
def settings_requires_https_put():
    """Stores whether the server should require the client to connect via HTTPS.

    Expects a JSON data structure in the request body that contains the new
    setting `requiresHttps` as bool. Example:
    {
        "requiresHttps": true
    }

    Returns:
        Empty response on success, error object otherwise.
    """
    try:
        should_be_required = request_parsers.requires_https.parse(flask.request)
    except request_parsers.errors.Error as e:
        return json_response.error(e), 400
    db.settings.Settings().set_requires_https(should_be_required)

    # Configure cookie security.
    is_session_cookie_secure = (not flask.current_app.debug and
                                should_be_required)
    flask.current_app.config.update(
        SESSION_COOKIE_SECURE=is_session_cookie_secure)

    return json_response.success()


@api_blueprint.route('/settings/video', methods=['GET'])
@required_auth(auth.Role.ADMIN)
def settings_video_get():
    """Retrieves the current video settings.

    Returns:
        On success, a JSON data structure with the following properties:
        - streamingMode: string
        - mjpegFrameRate: int
        - defaultMjpegFrameRate: int
        - mjpegQuality: int
        - defaultMjpegQuality: int
        - h264Bitrate: int
        - defaultH264Bitrate: int

        Example of success:
        {
            "streamingMode": "MJPEG",
            "mjpegFrameRate": 12,
            "defaultMjpegFrameRate": 30,
            "mjpegQuality": 80,
            "defaultMjpegQuality": 80,
            "h264Bitrate": 450,
            "defaultH264Bitrate": 5000
        }

        Returns an error object on failure.
    """
    try:
        update_settings = update.settings.load()
    except update.settings.LoadSettingsError as e:
        return json_response.error(e), 500

    streaming_mode = db.settings.Settings().get_streaming_mode().value

    return json_response.success({
        'streamingMode': streaming_mode,
        'mjpegFrameRate': update_settings.ustreamer_desired_fps,
        'defaultMjpegFrameRate': video_service.DEFAULT_MJPEG_FRAME_RATE,
        'mjpegQuality': update_settings.ustreamer_quality,
        'defaultMjpegQuality': video_service.DEFAULT_MJPEG_QUALITY,
        'h264Bitrate': update_settings.ustreamer_h264_bitrate,
        'defaultH264Bitrate': video_service.DEFAULT_H264_BITRATE,
        'h264StunServer': update_settings.janus_stun_server,
        'defaultH264StunServer': video_service.DEFAULT_H264_STUN_SERVER,
        'h264StunPort': update_settings.janus_stun_port,
        'defaultH264StunPort': video_service.DEFAULT_H264_STUN_PORT,
    })


@api_blueprint.route('/settings/video', methods=['PUT'])
@required_auth(auth.Role.ADMIN)
def settings_video_put():
    """Saves new video settings.

    Note: for the new settings to come into effect, you need to make a call to
    the /settings/video/apply endpoint afterwards.

    Expects a JSON data structure in the request body that contains the
    following parameters for the video settings:
    - streamingMode: string
    - mjpegFrameRate: int
    - mjpegQuality: int
    - h264Bitrate: int
    - h264StunServer: string (hostname or IP address), or null
    - h264StunPort: int, or null

    Note that the h264StunServer and h264StunPort parameters must either both be
    present, or both absent.

    Example of request body:
    {
        "streamingMode": "MJPEG",
        "mjpegFrameRate": 12,
        "mjpegQuality": 80,
        "h264Bitrate": 450,
        "h264StunServer": "stun.example.com",
        "h264StunPort": 3478
    }

    Returns:
        Empty response on success, error object otherwise.
    """
    try:
        streaming_mode = \
            request_parsers.video_settings.parse_streaming_mode(flask.request)
        mjpeg_frame_rate = \
            request_parsers.video_settings.parse_mjpeg_frame_rate(flask.request)
        mjpeg_quality = request_parsers.video_settings.parse_mjpeg_quality(
            flask.request)
        h264_bitrate = request_parsers.video_settings.parse_h264_bitrate(
            flask.request)
        h264_stun_server, h264_stun_port = \
            request_parsers.video_settings.parse_h264_stun_address(
                flask.request)
    except request_parsers.errors.InvalidVideoSettingError as e:
        return json_response.error(e), 400

    try:
        update_settings = update.settings.load()
    except update.settings.LoadSettingsError as e:
        return json_response.error(e), 500

    update_settings.ustreamer_desired_fps = mjpeg_frame_rate
    update_settings.ustreamer_quality = mjpeg_quality
    update_settings.ustreamer_h264_bitrate = h264_bitrate
    update_settings.janus_stun_server = h264_stun_server
    update_settings.janus_stun_port = h264_stun_port

    # Store the new parameters. Note: we only actually persist anything if *all*
    # values have passed the validation.
    db.settings.Settings().set_streaming_mode(streaming_mode)
    try:
        update.settings.save(update_settings)
    except update.settings.SaveSettingsError as e:
        return json_response.error(e), 500

    return json_response.success()


@api_blueprint.route('/settings/video/apply', methods=['POST'])
@required_auth(auth.Role.ADMIN)
def settings_video_apply_post():
    """Applies the current video settings found in the settings file.

    To allow the current video settings to take effect, we restart the video
    streaming services to reread the settings file and reinitialize the stream.

    Returns:
        Empty response.
    """
    video_service.restart()

    return json_response.success()


def _parse_keyboard_payload(payload):
    keystroke = request_parsers.keystroke.parse_keystroke(payload)
    hid_keystroke = js_to_hid.convert(keystroke)
    return keystroke, hid_keystroke


def _keyboard_press(hid_keystroke):
    keyboard_path = env.KEYBOARD_PATH
    fake_keyboard.send_keystroke(keyboard_path, hid_keystroke)


def _keyboard_hold(keystroke, hid_keystroke):
    with _pressed_lock:
        _pressed_keystrokes[keystroke.code] = hid_keystroke
        try:
            _send_current_pressed_state_locked()
        except TooManySimultaneousKeysError as error:
            del _pressed_keystrokes[keystroke.code]
            raise error
        except hid_write.WriteError as error:
            del _pressed_keystrokes[keystroke.code]
            raise error


def _keyboard_release(code=None):
    if code is None:
        _release_all_keys()
        return

    with _pressed_lock:
        hid_keystroke = _pressed_keystrokes.pop(code, None)
        if hid_keystroke is None:
            return
        try:
            _send_current_pressed_state_locked()
        except TooManySimultaneousKeysError as error:
            _clear_pressed_state_locked()
            need_reset = True
        except hid_write.WriteError as error:
            _pressed_keystrokes[code] = hid_keystroke
            raise error
        else:
            need_reset = False

    if need_reset:
        _release_all_keys()


def _handle_keyboard_press(payload):
    try:
        _, hid_keystroke = _parse_keyboard_payload(payload)
    except request_parsers.keystroke.Error as error:
        logger.error_sensitive('Failed to parse keyboard request: %s', error)
        return json_response.error(error), 400
    except js_to_hid.UnrecognizedKeyCodeError as error:
        logger.warning_sensitive('Unrecognized keycode in keyboard request: %s',
                                 error)
        return json_response.error(error), 400

    try:
        _keyboard_press(hid_keystroke)
    except hid_write.WriteError as error:
        logger.error_sensitive('Failed to write keyboard event: %s', error)
        return json_response.error(error), 500

    _restore_pressed_state()
    return json_response.success()


def _handle_keyboard_hold(payload):
    try:
        keystroke, hid_keystroke = _parse_keyboard_payload(payload)
    except request_parsers.keystroke.Error as error:
        logger.error_sensitive('Failed to parse keyboard hold request: %s',
                               error)
        return json_response.error(error), 400
    except js_to_hid.UnrecognizedKeyCodeError as error:
        logger.warning_sensitive(
            'Unrecognized keycode in keyboard hold request: %s', error)
        return json_response.error(error), 400

    try:
        _keyboard_hold(keystroke, hid_keystroke)
    except TooManySimultaneousKeysError as error:
        logger.warning_sensitive('Too many held keys requested: %s', error)
        return json_response.error(error), 400
    except hid_write.WriteError as error:
        logger.error_sensitive('Failed to hold keyboard key: %s', error)
        return json_response.error(error), 500

    return json_response.success()


def _handle_keyboard_release(code):
    try:
        _keyboard_release(code)
    except hid_write.WriteError as error:
        logger.error_sensitive('Failed to release keyboard keys: %s', error)
        return json_response.error(error), 500
    return json_response.success()


def _dispatch_keystrokes_async(keystrokes):
    """Schedules keystrokes to be written to the keyboard HID device."""
    keyboard_path = env.KEYBOARD_PATH

    def _write_keystrokes():
        try:
            fake_keyboard.send_keystrokes(keyboard_path, keystrokes)
        finally:
            _restore_pressed_state()

    execute.background_thread(_write_keystrokes)


def _compute_pressed_state_locked():
    modifier_mask = 0
    keycodes = []
    for code in sorted(_pressed_keystrokes):
        hid_keystroke = _pressed_keystrokes[code]
        modifier_mask |= hid_keystroke.modifier
        if hid_keystroke.keycode:
            keycodes.append(hid_keystroke.keycode)
    return modifier_mask, keycodes


def _send_current_pressed_state_locked():
    modifier_mask, keycodes = _compute_pressed_state_locked()
    if len(keycodes) > _MAX_SIMULTANEOUS_HID_KEYS:
        raise TooManySimultaneousKeysError(
            f'Cannot hold more than {_MAX_SIMULTANEOUS_HID_KEYS} simultaneous '
            'non-modifier keys')
    keyboard_path = env.KEYBOARD_PATH
    fake_keyboard.send_key_state(keyboard_path, modifier_mask, keycodes)


def _restore_pressed_state():
    with _pressed_lock:
        if not _pressed_keystrokes:
            return
        try:
            _send_current_pressed_state_locked()
        except TooManySimultaneousKeysError as error:
            logger.error_sensitive('Failed to restore held key state: %s', error)
        except hid_write.WriteError as error:
            logger.error_sensitive('Failed to rewrite held key state: %s', error)


def _clear_pressed_state_locked():
    _pressed_keystrokes.clear()


def _release_all_keys():
    with _pressed_lock:
        _clear_pressed_state_locked()
    keyboard_path = env.KEYBOARD_PATH
    fake_keyboard.release_keys(keyboard_path)


def _parse_absolute_cursor_event(payload):
    if not isinstance(payload, dict):
        raise request_parsers.errors.MalformedRequestError(
            'Request is invalid, expecting a JSON dictionary')

    required_fields = ('x', 'y', 'screenWidth', 'screenHeight')
    for field in required_fields:
        if field not in payload:
            raise request_parsers.errors.MissingFieldError(
                f'Missing required field: {field}')

    def _parse_coordinate(value, field_name):
        if not isinstance(value, (int, float)):
            raise request_parsers.errors.MalformedRequestError(
                f'{field_name} must be a number: {value}')
        return float(value)

    x = _parse_coordinate(payload['x'], 'x')
    y = _parse_coordinate(payload['y'], 'y')

    def _parse_dimension(value, field_name):
        if not isinstance(value, int):
            raise request_parsers.errors.MalformedRequestError(
                f'{field_name} must be an integer: {value}')
        if value <= 0:
            raise request_parsers.errors.MalformedRequestError(
                f'{field_name} must be greater than zero: {value}')
        return value

    width = _parse_dimension(payload['screenWidth'], 'screenWidth')
    height = _parse_dimension(payload['screenHeight'], 'screenHeight')

    relative_x = max(0.0, min(1.0, x / width))
    relative_y = max(0.0, min(1.0, y / height))

    buttons = payload.get('buttons', 0)
    if not isinstance(buttons, int):
        raise request_parsers.errors.MalformedRequestError(
            f'buttons must be an integer: {buttons}')

    vertical_wheel_delta = payload.get('verticalWheelDelta', 0)
    horizontal_wheel_delta = payload.get('horizontalWheelDelta', 0)

    cursor_event = {
        'buttons': buttons,
        'relativeX': relative_x,
        'relativeY': relative_y,
        'verticalWheelDelta': vertical_wheel_delta,
        'horizontalWheelDelta': horizontal_wheel_delta,
    }

    return request_parsers.mouse_event.parse_mouse_event(cursor_event)


_DEFAULT_MOUSE_EVENT = {
    'buttons': 0,
    'relativeX': 0.0,
    'relativeY': 0.0,
    'verticalWheelDelta': 0,
    'horizontalWheelDelta': 0,
}


def _parse_mouse_payload(payload, allow_defaults=False):
    if not isinstance(payload, dict):
        raise request_parsers.errors.MalformedRequestError(
            'Request is invalid, expecting a JSON dictionary')
    if allow_defaults:
        merged = dict(_DEFAULT_MOUSE_EVENT)
        merged.update(payload)
        return request_parsers.mouse_event.parse_mouse_event(merged)
    return request_parsers.mouse_event.parse_mouse_event(payload)


def _mouse_send(mouse_event):
    mouse_path = env.MOUSE_PATH
    fake_mouse.send_mouse_event(mouse_path, mouse_event.buttons,
                                mouse_event.relative_x,
                                mouse_event.relative_y,
                                mouse_event.vertical_wheel_delta,
                                mouse_event.horizontal_wheel_delta)


def _mouse_move(mouse_event):
    _mouse_send(mouse_event)
    with _mouse_lock:
        global _mouse_buttons_pressed
        _mouse_buttons_pressed = mouse_event.buttons


def _mouse_hold(button_mask, movement_event):
    if button_mask <= 0:
        raise request_parsers.mouse_event.InvalidButtonStateError(
            'buttons must be > 0 for hold operations')
    with _mouse_lock:
        global _mouse_buttons_pressed
        current = _mouse_buttons_pressed
        new_mask = current | button_mask
        event = request_parsers.mouse_event.MouseEvent(
            buttons=new_mask,
            relative_x=movement_event.relative_x,
            relative_y=movement_event.relative_y,
            vertical_wheel_delta=movement_event.vertical_wheel_delta,
            horizontal_wheel_delta=movement_event.horizontal_wheel_delta,
        )
        try:
            _mouse_send(event)
        except hid_write.WriteError as error:
            raise error
        _mouse_buttons_pressed = new_mask


def _mouse_release(button_mask, movement_event, *, release_all):
    with _mouse_lock:
        global _mouse_buttons_pressed
        current = _mouse_buttons_pressed
        if release_all:
            new_mask = 0
        elif button_mask <= 0:
            raise request_parsers.mouse_event.InvalidButtonStateError(
                'buttons must be > 0 for targeted release operations')
        else:
            new_mask = current & ~button_mask
        event = request_parsers.mouse_event.MouseEvent(
            buttons=new_mask,
            relative_x=movement_event.relative_x,
            relative_y=movement_event.relative_y,
            vertical_wheel_delta=movement_event.vertical_wheel_delta,
            horizontal_wheel_delta=movement_event.horizontal_wheel_delta,
        )
        try:
            _mouse_send(event)
        except hid_write.WriteError as error:
            raise error
        _mouse_buttons_pressed = new_mask


def _mouse_press(button_mask, movement_event):
    if button_mask <= 0:
        raise request_parsers.mouse_event.InvalidButtonStateError(
            'buttons must be > 0 for press operations')
    with _mouse_lock:
        current = _mouse_buttons_pressed
        new_mask = current | button_mask
        press_event = request_parsers.mouse_event.MouseEvent(
            buttons=new_mask,
            relative_x=movement_event.relative_x,
            relative_y=movement_event.relative_y,
            vertical_wheel_delta=movement_event.vertical_wheel_delta,
            horizontal_wheel_delta=movement_event.horizontal_wheel_delta,
        )
        release_event = request_parsers.mouse_event.MouseEvent(
            buttons=current,
            relative_x=0.0,
            relative_y=0.0,
            vertical_wheel_delta=0,
            horizontal_wheel_delta=0,
        )
        try:
            _mouse_send(press_event)
            _mouse_send(release_event)
        except hid_write.WriteError as error:
            raise error
        _mouse_buttons_pressed = current


def _handle_mouse_move(payload, *, allow_defaults):
    try:
        mouse_event = _parse_mouse_payload(payload, allow_defaults=allow_defaults)
    except request_parsers.mouse_event.Error as error:
        logger.error_sensitive('Failed to parse mouse request: %s', error)
        return json_response.error(error), 400

    try:
        _mouse_move(mouse_event)
    except hid_write.WriteError as error:
        logger.error_sensitive('Failed to forward mouse event: %s', error)
        return json_response.error(error), 500

    return json_response.success()


def _handle_mouse_hold(payload):
    if not isinstance(payload, dict):
        error = request_parsers.errors.MalformedRequestError(
            'Request is invalid, expecting a JSON dictionary')
        return json_response.error(error), 400
    if 'buttons' not in payload:
        error = request_parsers.errors.MissingFieldError(
            'Missing required field: buttons')
        return json_response.error(error), 400

    try:
        mouse_event = _parse_mouse_payload(payload, allow_defaults=True)
        _mouse_hold(mouse_event.buttons, mouse_event)
    except request_parsers.mouse_event.InvalidButtonStateError as error:
        logger.error_sensitive('Invalid mouse hold request: %s', error)
        return json_response.error(error), 400
    except request_parsers.mouse_event.Error as error:
        logger.error_sensitive('Failed to parse mouse hold request: %s', error)
        return json_response.error(error), 400
    except hid_write.WriteError as error:
        logger.error_sensitive('Failed to hold mouse buttons: %s', error)
        return json_response.error(error), 500

    return json_response.success()


def _handle_mouse_release(payload):
    if not isinstance(payload, dict):
        error = request_parsers.errors.MalformedRequestError(
            'Request is invalid, expecting a JSON dictionary')
        return json_response.error(error), 400
    release_all = 'buttons' not in payload
    try:
        mouse_event = _parse_mouse_payload(payload, allow_defaults=True)
    except request_parsers.mouse_event.Error as error:
        logger.error_sensitive('Failed to parse mouse release request: %s', error)
        return json_response.error(error), 400

    button_mask = mouse_event.buttons
    try:
        _mouse_release(button_mask, mouse_event, release_all=release_all)
    except request_parsers.mouse_event.InvalidButtonStateError as error:
        logger.error_sensitive('Invalid mouse release request: %s', error)
        return json_response.error(error), 400
    except hid_write.WriteError as error:
        logger.error_sensitive('Failed to release mouse buttons: %s', error)
        return json_response.error(error), 500

    return json_response.success()


def _handle_mouse_press(payload):
    if not isinstance(payload, dict):
        error = request_parsers.errors.MalformedRequestError(
            'Request is invalid, expecting a JSON dictionary')
        return json_response.error(error), 400
    if 'buttons' not in payload:
        error = request_parsers.errors.MissingFieldError(
            'Missing required field: buttons')
        return json_response.error(error), 400

    try:
        mouse_event = _parse_mouse_payload(payload, allow_defaults=True)
        _mouse_press(mouse_event.buttons, mouse_event)
    except request_parsers.mouse_event.InvalidButtonStateError as error:
        logger.error_sensitive('Invalid mouse press request: %s', error)
        return json_response.error(error), 400
    except request_parsers.mouse_event.Error as error:
        logger.error_sensitive('Failed to parse mouse press request: %s', error)
        return json_response.error(error), 400
    except hid_write.WriteError as error:
        logger.error_sensitive('Failed to issue mouse press: %s', error)
        return json_response.error(error), 500

    return json_response.success()


@api_blueprint.route('/hid/keyboard', methods=['POST'])
@required_auth(auth.Role.OPERATOR)
def hid_keyboard_post():
    """Sends a single keyboard event to the target machine via REST."""
    payload = flask.request.get_json()
    logger.debug_sensitive('REST keyboard request payload: %s', payload)
    return _handle_keyboard_press(payload)


@api_blueprint.route('/hid/keyboard/press', methods=['POST'])
@required_auth(auth.Role.OPERATOR)
def hid_keyboard_press_post():
    """Alias endpoint for sending a single keyboard press."""
    payload = flask.request.get_json()
    logger.debug_sensitive('REST keyboard press payload: %s', payload)
    return _handle_keyboard_press(payload)


@api_blueprint.route('/hid/keyboard/hold', methods=['POST'])
@required_auth(auth.Role.OPERATOR)
def hid_keyboard_hold_post():
    """Holds a key (and optional modifiers) down until explicitly released."""
    payload = flask.request.get_json()
    logger.debug_sensitive('REST keyboard hold payload: %s', payload)
    return _handle_keyboard_hold(payload)


@api_blueprint.route('/hid/keyboard/release', methods=['POST'])
@required_auth(auth.Role.OPERATOR)
def hid_keyboard_release_post():
    """Releases keys on the virtual keyboard.

    If the request body contains a "code" field, only the corresponding key is
    released. Otherwise, all currently held keys are released.
    """
    payload = flask.request.get_json(silent=True)
    if not isinstance(payload, dict) or 'code' not in payload:
        return _handle_keyboard_release(None)

    key_code = payload.get('code')
    if not isinstance(key_code, str):
        error = request_parsers.errors.MalformedRequestError(
            'The code field must be a string')
        return json_response.error(error), 400

    return _handle_keyboard_release(key_code)


@api_blueprint.route('/hid/mouse', methods=['POST', 'PUT'])
@required_auth(auth.Role.OPERATOR)
def hid_mouse_post():
    """Sends a mouse event to the target machine via REST."""
    payload = flask.request.get_json()
    logger.debug_sensitive('REST mouse request payload: %s', payload)
    return _handle_mouse_move(payload, allow_defaults=False)


@api_blueprint.route('/hid/mouse/press', methods=['POST'])
@required_auth(auth.Role.OPERATOR)
def hid_mouse_press_post():
    payload = flask.request.get_json()
    logger.debug_sensitive('REST mouse press payload: %s', payload)
    return _handle_mouse_press(payload)


@api_blueprint.route('/hid/mouse/hold', methods=['POST'])
@required_auth(auth.Role.OPERATOR)
def hid_mouse_hold_post():
    payload = flask.request.get_json()
    logger.debug_sensitive('REST mouse hold payload: %s', payload)
    return _handle_mouse_hold(payload)


@api_blueprint.route('/hid/mouse/release', methods=['POST'])
@required_auth(auth.Role.OPERATOR)
def hid_mouse_release_post():
    payload = flask.request.get_json(silent=True)
    if payload is None:
        payload = {}
    logger.debug_sensitive('REST mouse release payload: %s', payload)
    return _handle_mouse_release(payload)


@api_blueprint.route('/hid/macro', methods=['POST'])
@required_auth(auth.Role.OPERATOR)
def hid_macro_post():
    """Replays a sequence of keyboard/mouse events and delays."""
    logger.debug_sensitive('REST macro payload: %s', flask.request.get_json())

    try:
        events = request_parsers.macro.parse_macro(flask.request)
    except request_parsers.macro.Error as error:
        logger.error_sensitive('Failed to parse macro request: %s', error)
        return json_response.error(error), 400

    def _run_macro():
        for step in events:
            if step.kind == 'keyboard_press':
                keystroke = step.data
                try:
                    hid_keystroke = js_to_hid.convert(keystroke)
                    _keyboard_press(hid_keystroke)
                except js_to_hid.UnrecognizedKeyCodeError as exc:
                    logger.warning_sensitive('Macro contains unknown key: %s',
                                             exc)
                    break
                except hid_write.WriteError as exc:
                    logger.error_sensitive('Failed to send macro keystroke: %s',
                                           exc)
                    break
                _restore_pressed_state()
                if step.delay_ms:
                    time.sleep(step.delay_ms / 1000)
                continue

            if step.kind == 'keyboard_hold':
                keystroke = step.data
                try:
                    hid_keystroke = js_to_hid.convert(keystroke)
                    _keyboard_hold(keystroke, hid_keystroke)
                except js_to_hid.UnrecognizedKeyCodeError as exc:
                    logger.warning_sensitive('Macro contains unknown key: %s',
                                             exc)
                    break
                except TooManySimultaneousKeysError as exc:
                    logger.warning_sensitive('Macro attempted to hold too many '
                                             'keys: %s', exc)
                    break
                except hid_write.WriteError as exc:
                    logger.error_sensitive('Failed to hold macro keyboard key: %s',
                                           exc)
                    break
                if step.delay_ms:
                    time.sleep(step.delay_ms / 1000)
                continue

            if step.kind == 'keyboard_release':
                try:
                    _keyboard_release(step.data)
                except hid_write.WriteError as exc:
                    logger.error_sensitive('Failed to release macro keyboard '
                                           'keys: %s', exc)
                    break
                if step.delay_ms:
                    time.sleep(step.delay_ms / 1000)
                continue

            if step.kind == 'mouse_move':
                try:
                    _mouse_move(step.data)
                except hid_write.WriteError as exc:
                    logger.error_sensitive('Failed to send macro mouse event: %s',
                                           exc)
                    break
                if step.delay_ms:
                    time.sleep(step.delay_ms / 1000)
                continue

            if step.kind == 'mouse_hold':
                mouse_event = step.data
                try:
                    _mouse_hold(mouse_event.buttons, mouse_event)
                except request_parsers.mouse_event.InvalidButtonStateError as exc:
                    logger.error_sensitive('Invalid mouse hold in macro: %s', exc)
                    break
                except hid_write.WriteError as exc:
                    logger.error_sensitive('Failed to hold macro mouse buttons: %s',
                                           exc)
                    break
                if step.delay_ms:
                    time.sleep(step.delay_ms / 1000)
                continue

            if step.kind == 'mouse_press':
                mouse_event = step.data
                try:
                    _mouse_press(mouse_event.buttons, mouse_event)
                except request_parsers.mouse_event.InvalidButtonStateError as exc:
                    logger.error_sensitive('Invalid mouse press in macro: %s', exc)
                    break
                except hid_write.WriteError as exc:
                    logger.error_sensitive('Failed to press macro mouse buttons: %s',
                                           exc)
                    break
                if step.delay_ms:
                    time.sleep(step.delay_ms / 1000)
                continue

            if step.kind == 'mouse_release':
                info = step.data
                mouse_event = info['event']
                release_all = info['release_all']
                try:
                    _mouse_release(mouse_event.buttons,
                                   mouse_event,
                                   release_all=release_all)
                except request_parsers.mouse_event.InvalidButtonStateError as exc:
                    logger.error_sensitive('Invalid mouse release in macro: %s',
                                           exc)
                    break
                except hid_write.WriteError as exc:
                    logger.error_sensitive('Failed to release macro mouse '
                                           'buttons: %s', exc)
                    break
                if step.delay_ms:
                    time.sleep(step.delay_ms / 1000)
                continue

            if step.kind == 'delay':
                time.sleep(step.data / 1000)
                continue

    execute.background_thread(_run_macro)

    return json_response.success()


@api_blueprint.route('/hid/cursor', methods=['POST', 'PUT'])
@required_auth(auth.Role.OPERATOR)
def hid_cursor_post():
    """Moves the cursor using absolute pixel coordinates."""
    payload = flask.request.get_json()
    logger.debug_sensitive('REST cursor payload: %s', payload)

    try:
        mouse_event = _parse_absolute_cursor_event(payload)
    except request_parsers.errors.Error as error:
        logger.error_sensitive('Failed to parse cursor request: %s', error)
        return json_response.error(error), 400

    mouse_path = env.MOUSE_PATH
    try:
        fake_mouse.send_mouse_event(mouse_path, mouse_event.buttons,
                                    mouse_event.relative_x,
                                    mouse_event.relative_y,
                                    mouse_event.vertical_wheel_delta,
                                    mouse_event.horizontal_wheel_delta)
    except hid_write.WriteError as error:
        logger.error_sensitive('Failed to write cursor event: %s', error)
        return json_response.error(error), 500

    return json_response.success()


@api_blueprint.route('/hid/keymap', methods=['GET'])
@required_auth(auth.Role.OPERATOR)
def hid_keymap_get():
    """Returns the available keyboard codes and hardware keycodes."""
    key_map = js_to_hid.get_key_map()
    response = {
        'keys': [{'code': code, 'hidCode': key_map[code]} for code in key_map],
        'modifierCodes': js_to_hid.get_modifier_codes(),
        'maxSimultaneousNonModifierKeys': _MAX_SIMULTANEOUS_HID_KEYS,
    }
    return json_response.success(response)


@api_blueprint.route('/hid/mouse-info', methods=['GET'])
@required_auth(auth.Role.OPERATOR)
def hid_mouse_info_get():
    """Returns the supported mouse limits."""
    capabilities = request_parsers.mouse_event.get_capabilities()
    capabilities['wheelDeltaValues'] = list(capabilities['wheelDeltaValues'])
    return json_response.success(capabilities)


@api_blueprint.route('/hid/paste', methods=['POST'])
@required_auth(auth.Role.OPERATOR)
def hid_paste_post():
    """Types a full string onto the target machine via REST."""
    payload = flask.request.get_json()
    logger.debug_sensitive('REST paste request payload: %s', payload)

    if not isinstance(payload, dict):
        error = request_parsers.errors.MalformedRequestError(
            'Request is invalid, expecting a JSON dictionary')
        logger.error_sensitive('Failed to parse paste request: %s', error)
        return json_response.error(error), 400

    paste_payload = dict(payload)
    paste_payload.setdefault('language', 'en-US')

    class _PasteRequest:

        def __init__(self, body):
            self._body = body

        def get_json(self):
            return self._body

    try:
        keystrokes = request_parsers.paste.parse_keystrokes(
            _PasteRequest(paste_payload))
    except request_parsers.errors.Error as e:
        logger.error_sensitive('Failed to convert paste request: %s', e)
        return json_response.error(e), 400

    _dispatch_keystrokes_async(keystrokes)

    return json_response.success()


@api_blueprint.route('/paste', methods=['POST'])
@required_auth(auth.Role.OPERATOR)
def paste_post():
    """Pastes text onto the target machine.

    Expects a JSON data structure in the request body that contains the
    following parameters:
    - text: string
    - language: string as an IETF language tag

    Example of request body:
    {
        "text": "Hello, World!",
        "language": "en-US"
    }
    """
    try:
        keystrokes = request_parsers.paste.parse_keystrokes(flask.request)
    except request_parsers.errors.Error as e:
        return json_response.error(e), 400

    _dispatch_keystrokes_async(keystrokes)

    return json_response.success()
