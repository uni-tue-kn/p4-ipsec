class TunnelException(Exception):
    """Base class for tunnel exceptions"""


class TargetUnknown(TunnelException):
    pass


class TunnelUnknown(TunnelException):
    pass


class RequestDenied(TunnelException):
    pass
