# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
import grpc

import client_pb2 as client__pb2


class TunnelServiceStub(object):
  # missing associated documentation comment in .proto file
  pass

  def __init__(self, channel):
    """Constructor.

    Args:
      channel: A grpc.Channel.
    """
    self.requestTunnelByIP = channel.unary_unary(
        '/TunnelService/requestTunnelByIP',
        request_serializer=client__pb2.request.SerializeToString,
        response_deserializer=client__pb2.tunnel.FromString,
        )
    self.renewTunnelByIP = channel.unary_unary(
        '/TunnelService/renewTunnelByIP',
        request_serializer=client__pb2.request.SerializeToString,
        response_deserializer=client__pb2.tunnel.FromString,
        )
    self.deleteTunnelByIP = channel.unary_unary(
        '/TunnelService/deleteTunnelByIP',
        request_serializer=client__pb2.request.SerializeToString,
        response_deserializer=client__pb2.status.FromString,
        )


class TunnelServiceServicer(object):
  # missing associated documentation comment in .proto file
  pass

  def requestTunnelByIP(self, request, context):
    # missing associated documentation comment in .proto file
    pass
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def renewTunnelByIP(self, request, context):
    # missing associated documentation comment in .proto file
    pass
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def deleteTunnelByIP(self, request, context):
    # missing associated documentation comment in .proto file
    pass
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')


def add_TunnelServiceServicer_to_server(servicer, server):
  rpc_method_handlers = {
      'requestTunnelByIP': grpc.unary_unary_rpc_method_handler(
          servicer.requestTunnelByIP,
          request_deserializer=client__pb2.request.FromString,
          response_serializer=client__pb2.tunnel.SerializeToString,
      ),
      'renewTunnelByIP': grpc.unary_unary_rpc_method_handler(
          servicer.renewTunnelByIP,
          request_deserializer=client__pb2.request.FromString,
          response_serializer=client__pb2.tunnel.SerializeToString,
      ),
      'deleteTunnelByIP': grpc.unary_unary_rpc_method_handler(
          servicer.deleteTunnelByIP,
          request_deserializer=client__pb2.request.FromString,
          response_serializer=client__pb2.status.SerializeToString,
      ),
  }
  generic_handler = grpc.method_handlers_generic_handler(
      'TunnelService', rpc_method_handlers)
  server.add_generic_rpc_handlers((generic_handler,))
