"""Application entry point for LootCheck."""

import logging
from src.utils.logging_config import setup_logging

logger = logging.getLogger('LootCheck')


def create_app():
    """Create and return the application root window."""
    setup_logging()
    logger.info("Starting LootCheck application")

    # Try to use tkinterdnd2 for drag-and-drop support
    root = None
    try:
        import tkinterdnd2
        root = tkinterdnd2.Tk()
        logger.info("Using tkinterdnd2 for drag-and-drop support")
    except ImportError:
        logger.warning("tkinterdnd2 not available — using standard Tk (no drag-and-drop)")
    except Exception as e:
        logger.warning("Failed to initialize tkinterdnd2: %s — using standard Tk", e)

    if root is None:
        import tkinter as tk
        root = tk.Tk()

    return root


def run():
    """Run the LootCheck application."""
    root = create_app()

    from src.ui.main_window import MainWindow
    app = MainWindow(root)

    try:
        root.mainloop()
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
    except Exception as e:
        logger.exception("Application crashed: %s", e)
        raise
    finally:
        logger.info("LootCheck shutdown")
