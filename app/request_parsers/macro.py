import dataclasses
import typing

import js_to_hid
from request_parsers import errors
from request_parsers import keystroke as keystroke_request
from request_parsers import mouse_event as mouse_event_request


class Error(Exception):
    pass


class InvalidEventTypeError(Error):
    pass


class InvalidDelayError(Error):
    pass


class MalformedRequestError(Error):
    pass


class MissingFieldError(Error):
    pass


_MAX_DELAY_MS = 60000

_DEFAULT_MOUSE_EVENT = {
    'buttons': 0,
    'relativeX': 0.0,
    'relativeY': 0.0,
    'verticalWheelDelta': 0,
    'horizontalWheelDelta': 0,
}


@dataclasses.dataclass
class MacroStep:
    kind: str
    data: typing.Any
    delay_ms: int = 0


def parse_macro(request) -> typing.List[MacroStep]:
    payload = request.get_json()

    if not isinstance(payload, dict):
        raise MalformedRequestError(
            'Request is invalid, expecting a JSON dictionary')

    if 'events' not in payload:
        raise MissingFieldError('Missing required field: events')

    events = payload['events']
    if not isinstance(events, list):
        raise MalformedRequestError('Field events must be an array of objects')

    parsed_steps = []
    for raw_event in events:
        if not isinstance(raw_event, dict):
            raise MalformedRequestError('Macro events must be JSON objects')

        event_type = raw_event.get('type')
        if event_type is None:
            raise MissingFieldError('Macro events must include a type field')

        delay_ms = _parse_optional_delay(raw_event.get('delayMs', 0))

        event_payload = dict(raw_event)
        event_payload.pop('type', None)
        event_payload.pop('delayMs', None)

        if event_type in ('keyboard', 'keyboardPress'):
            keystroke = keystroke_request.parse_keystroke(event_payload)
            try:
                js_to_hid.convert(keystroke)
            except js_to_hid.UnrecognizedKeyCodeError as exc:
                raise InvalidEventTypeError(str(exc)) from exc
            parsed_steps.append(
                MacroStep(kind='keyboard_press', data=keystroke, delay_ms=delay_ms))
            continue

        if event_type == 'keyboardHold':
            keystroke = keystroke_request.parse_keystroke(event_payload)
            try:
                js_to_hid.convert(keystroke)
            except js_to_hid.UnrecognizedKeyCodeError as exc:
                raise InvalidEventTypeError(str(exc)) from exc
            parsed_steps.append(
                MacroStep(kind='keyboard_hold', data=keystroke, delay_ms=delay_ms))
            continue

        if event_type == 'keyboardRelease':
            code = event_payload.get('code')
            if code is not None and not isinstance(code, str):
                raise MalformedRequestError(
                    f'The code field must be a string: {code}')
            parsed_steps.append(
                MacroStep(kind='keyboard_release', data=code, delay_ms=delay_ms))
            continue

        if event_type in ('mouse', 'mouseMove'):
            mouse_event = mouse_event_request.parse_mouse_event(event_payload)
            parsed_steps.append(
                MacroStep(kind='mouse_move', data=mouse_event, delay_ms=delay_ms))
            continue

        if event_type == 'mouseHold':
            if 'buttons' not in event_payload:
                raise MissingFieldError('Missing required field: buttons')
            mouse_event = _parse_mouse_event_with_defaults(event_payload)
            parsed_steps.append(
                MacroStep(kind='mouse_hold', data=mouse_event, delay_ms=delay_ms))
            continue

        if event_type == 'mousePress':
            if 'buttons' not in event_payload:
                raise MissingFieldError('Missing required field: buttons')
            mouse_event = _parse_mouse_event_with_defaults(event_payload)
            parsed_steps.append(
                MacroStep(kind='mouse_press', data=mouse_event, delay_ms=delay_ms))
            continue

        if event_type == 'mouseRelease':
            release_all = 'buttons' not in event_payload
            mouse_event = _parse_mouse_event_with_defaults(event_payload)
            parsed_steps.append(
                MacroStep(kind='mouse_release',
                          data={'event': mouse_event, 'release_all': release_all},
                          delay_ms=delay_ms))
            continue

        if event_type == 'delay':
            duration_ms = _parse_required_delay(event_payload.get('ms'))
            parsed_steps.append(MacroStep(kind='delay', data=duration_ms))
            continue

        raise InvalidEventTypeError(f'Unsupported macro event type: {event_type}')

    return parsed_steps


def _parse_mouse_event_with_defaults(payload):
    merged = dict(_DEFAULT_MOUSE_EVENT)
    merged.update(payload)
    return mouse_event_request.parse_mouse_event(merged)


def _parse_optional_delay(value):
    if value is None:
        return 0
    _validate_delay(value, allow_zero=True)
    return value


def _parse_required_delay(value):
    if value is None:
        raise MissingFieldError('Missing required field: ms')
    _validate_delay(value, allow_zero=False)
    return value


def _validate_delay(value, *, allow_zero):
    if not isinstance(value, int):
        raise InvalidDelayError(
            f'Delay must be an integer number of milliseconds: {value}')
    if value < 0 or (not allow_zero and value == 0):
        raise InvalidDelayError(f'Delay must be positive: {value}')
    if value > _MAX_DELAY_MS:
        raise InvalidDelayError(
            f'Delay cannot exceed {_MAX_DELAY_MS} milliseconds: {value}')
