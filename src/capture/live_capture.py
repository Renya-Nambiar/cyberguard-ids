from scapy.arch.windows import get_windows_if_list
from scapy.all import sniff, IFACES
import logging

logger = logging.getLogger(__name__)


def list_interfaces():
    """
    Return all interfaces Scapy can see, enriched with Scapy's
    canonical device name so the UI can pass a sniffable value
    directly.
    """
    result = []
    for iface in get_windows_if_list():
        # Scapy's internal name as used by sniff(iface=...)
        dev = None
        try:
            # Map Windows GUID / name to Scapy interface object
            scapy_if = IFACES.get(iface.get("name")) or IFACES.get(iface.get("guid"))
            if scapy_if:
                dev = scapy_if.name
        except Exception:
            pass

        result.append({
            "name": iface.get("name"),
            "description": iface.get("description"),
            "guid": iface.get("guid"),
            "win_name": iface.get("win_name"),
            "ips": iface.get("ips"),
            "device": dev,          # <- sniffable value when not None
        })
    return result


def resolve_interface(friendly_name):
    """
    Map friendly name (what you show in the UI) to a value that
    sniff() accepts. Prefer Scapy's device name, then win_name.
    Do NOT synthesize '\\Device\\NPF_...' yourself.
    """
    for iface in list_interfaces():
        if iface.get("name") == friendly_name:
            dev = iface.get("device") or iface.get("win_name")
            logger.info("Resolved '%s' to '%s'", friendly_name, dev)
            return dev
    logger.warning("No match found for '%s'", friendly_name)
    return None


def capture_packets(friendly_name, duration=15):
    """
    Sniff packets from the selected interface for given duration.
    Raises a clear error if Scapy cannot open the adapter.
    """
    dev = resolve_interface(friendly_name)
    if not dev:
        msg = f"No usable device for interface '{friendly_name}'"
        logger.error(msg)
        raise RuntimeError(msg)

    try:
        logger.info("Sniffing on '%s' for %ss", dev, duration)
        return sniff(iface=dev, timeout=duration)
    except Exception as e:
        logger.error("Error opening adapter '%s': %s", dev, e)
        raise RuntimeError(f"Error opening adapter: {e}")
