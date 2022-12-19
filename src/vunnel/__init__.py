import logging


def patch_logger():  # type: ignore
    TRACE_LEVEL_NUM = 9
    logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")

    def trace(self, message, *args, **kws):  # type: ignore
        if self.isEnabledFor(TRACE_LEVEL_NUM):
            self._log(TRACE_LEVEL_NUM, message, args, **kws)  # noqa

    logging.Logger.trace = trace  # type: ignore


# note: this needs to be made available to the rest of the application and tests
patch_logger()
