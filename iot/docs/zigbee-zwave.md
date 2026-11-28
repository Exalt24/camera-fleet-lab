# Zigbee and Z-Wave: not built, and what the bridge would be

**Nothing in this repository speaks Zigbee or Z-Wave, and no radio hardware was used.** There was no coordinator stick, no Zigbee or Z-Wave lock and no radio test of any kind. The slice proves the MQTT side, the vendor cloud side and the integration logic between them, with a simulated lock.

## What the bridge would be

Zigbee and Z-Wave locks do not talk to a broker or to a cloud. They talk to a radio coordinator, and a gateway program turns that into MQTT:

| Radio | Gateway | Hardware it needs |
|---|---|---|
| Zigbee | Zigbee2MQTT (a USB Zigbee coordinator, a paired lock) | a coordinator stick and a Zigbee lock |
| Z-Wave | Z-Wave JS (with Z-Wave JS UI or Z-Wave JS MQTT publishing to a broker) | a Z-Wave controller stick and a Z-Wave lock |

Each gateway publishes a lock's state to an MQTT topic and listens on a set topic for commands. To use one with this slice, a small adapter would map that gateway's topic and payload names onto the lock topics in [`contract.md`](contract.md) (`locks/<id>/state`, `locks/<id>/status`, `locks/<id>/cmd`), or the connector's MQTT listener would be given a second topic mapping. The connector, the record, the diagnosis tool and the tests would not change, because they only know the lock topics.

## What the gateway would add that the simulator does not model

- **Pairing and inclusion.** A Zigbee or Z-Wave lock has to be put in a pairing mode and joined to the network. Z-Wave S2 security uses a device key (often printed on the lock as a DSK), and that key is a credential like any other here.
- **A mesh.** Battery locks are leaf nodes. They sleep, so a command can wait for a wake up, and a weak route looks like an offline lock when it is really a poor mesh. The simulator's cut and blackhole link modes stand for the broker side of that, not for radio behaviour.
- **Capability reporting.** Zigbee exposes clusters (door lock, power configuration) and Z-Wave exposes command classes (Door Lock, User Code, Battery). Reading what a given lock really supports, when the maker's documentation is thin, is real work on real hardware and was not done here.
- **User codes on the lock.** In Z-Wave the User Code command class stores PINs on the device. The stand in vendor never pushes codes to the lock, so this path is untested.

## Where this would go in the diagnosis tool

A bridge adds a layer between the broker and the device: gateway process, coordinator, radio link. The probes in `iot/iotlab/diagnose.py` are ordered by data flow, so the new layer would be inserted between `broker` and `device` with its own evidence (gateway log, coordinator reachable, last seen time of the node). It is not written.
