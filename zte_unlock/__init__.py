"""Clean-room tooling for ZTE ONU factory mode.

Independent implementation of the ZTE ONT factory-mode handshake, written so
the procedure does not depend on any single upstream binary continuing to exist.

Protocol constants (endpoints, key material, command strings) are interop facts
defined by the ONT firmware. All logic, structure and naming here are original.

See NOTICE.md for upstream credits and licenses.
"""

from .factory_mode import FactoryError, FactoryMode, open_factory_mode

__version__ = "1.0.0"

__all__ = ["FactoryError", "FactoryMode", "open_factory_mode", "__version__"]