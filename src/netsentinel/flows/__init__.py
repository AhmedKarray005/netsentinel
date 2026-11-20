"""Flow aggregation: groups packets into conversations between two endpoints."""

from netsentinel.flows.aggregator import FlowAggregator, flow_key
from netsentinel.flows.models import Flow
from netsentinel.flows.stats import flow_report, top_conversations, top_talkers

__all__ = ["Flow", "FlowAggregator", "flow_key", "flow_report", "top_conversations", "top_talkers"]
