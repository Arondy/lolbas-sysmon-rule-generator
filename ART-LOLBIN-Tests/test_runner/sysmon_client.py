import time
import xml.etree.ElementTree as ET

import win32evtlog

from .models import MarkerEvent

XML_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def close_evt_handle(handle: object | None) -> None:
    if handle is None:
        return

    close_func = getattr(win32evtlog, "EvtClose", None)
    if callable(close_func):
        close_func(handle)
        return

    close_method = getattr(handle, "Close", None)
    if callable(close_method):
        close_method()


def query_events(
    channel: str,
    xpath_query: str,
    reverse: bool,
    batch_size: int,
    max_events: int = 0,
) -> list[MarkerEvent]:
    flags = win32evtlog.EvtQueryChannelPath
    if reverse:
        flags |= win32evtlog.EvtQueryReverseDirection
    else:
        flags |= win32evtlog.EvtQueryForwardDirection

    query_handle = win32evtlog.EvtQuery(channel, flags, xpath_query)
    events: list[MarkerEvent] = []

    try:
        while True:
            handles = win32evtlog.EvtNext(query_handle, batch_size, 0, 0)
            if not handles:
                break

            for handle in handles:
                try:
                    xml_text = win32evtlog.EvtRender(handle, win32evtlog.EvtRenderEventXml)
                    event = parse_event_xml(xml_text)
                    if event is not None:
                        events.append(event)
                finally:
                    close_evt_handle(handle)

                if max_events > 0 and len(events) >= max_events:
                    return events
    finally:
        close_evt_handle(query_handle)

    return events


def parse_event_xml(xml_text: str) -> MarkerEvent | None:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    record_id_text = root.findtext("./e:System/e:EventRecordID", namespaces=XML_NS)
    event_id_text = root.findtext("./e:System/e:EventID", namespaces=XML_NS)
    time_node = root.find("./e:System/e:TimeCreated", namespaces=XML_NS)
    rule_name_node = root.find("./e:EventData/e:Data[@Name='RuleName']", namespaces=XML_NS)
    command_node = root.find("./e:EventData/e:Data[@Name='CommandLine']", namespaces=XML_NS)

    if not record_id_text or not event_id_text or time_node is None:
        return None

    system_time_utc = str(time_node.attrib.get("SystemTime", ""))
    rule_name = rule_name_node.text if rule_name_node is not None and rule_name_node.text else ""
    command_line = command_node.text if command_node is not None and command_node.text else ""

    return MarkerEvent(
        record_id=int(record_id_text),
        event_id=int(event_id_text),
        system_time_utc=system_time_utc,
        rule_name=rule_name,
        command_line=command_line,
    )


def find_marker_event(
    channel: str,
    marker_token: str,
    timeout_seconds: int,
    poll_interval_seconds: float,
    scan_limit: int,
    batch_size: int,
) -> MarkerEvent | None:
    deadline = time.time() + timeout_seconds
    query = "*[System[(EventID=1)]]"

    while time.time() <= deadline:
        events = query_events(
            channel=channel,
            xpath_query=query,
            reverse=True,
            batch_size=batch_size,
            max_events=scan_limit,
        )
        for event in events:
            if marker_token in event.command_line:
                return event
        time.sleep(poll_interval_seconds)

    return None


def get_window_events(
    channel: str,
    start_record_id: int,
    end_record_id: int,
    batch_size: int,
) -> list[MarkerEvent]:
    query = f"*[System[(EventRecordID >= {start_record_id} and EventRecordID <= {end_record_id})]]"
    return query_events(
        channel=channel,
        xpath_query=query,
        reverse=False,
        batch_size=batch_size,
        max_events=0,
    )
