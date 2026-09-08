"""GraphQL 检测模块（lite）。"""

from .detector import GraphQLDetector, _is_introspection_response, _looks_like_graphql

__all__ = ["GraphQLDetector", "_looks_like_graphql", "_is_introspection_response"]
