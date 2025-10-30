"""
DMARRSS Threat Scoring Engine
Implements Context Aware Event Severity Layers and threat prioritization
"""

import numpy as np
from typing import Dict, List, Any, Tuple
from datetime import datetime
from ..utils.config import ConfigLoader, DMALogger


class ThreatScorer:
    """
    Core threat scoring engine with Context Aware Event Severity Layers.
    Implements neural-inspired prioritization of security events.
    """
    
    def __init__(self, config: ConfigLoader = None):
        self.config = config or ConfigLoader()
        self.logger = DMALogger('ThreatScorer', self.config)
        self.scoring_weights = self.config.get_scoring_weights()
        
        # Initialize threat knowledge base (simple pattern matching)
        self._init_threat_patterns()
        
    def _init_threat_patterns(self):
        """Initialize known threat patterns for pattern matching"""
        self.threat_patterns = {
            'exploit': {
                'keywords': ['exploit', 'overflow', 'injection', 'shellcode', 'RCE'],
                'base_score': 0.9
            },
            'malware': {
                'keywords': ['malware', 'trojan', 'virus', 'ransomware', 'backdoor'],
                'base_score': 0.85
            },
            'scan': {
                'keywords': ['scan', 'probe', 'reconnaissance', 'enumeration'],
                'base_score': 0.4
            },
            'dos': {
                'keywords': ['dos', 'ddos', 'flood', 'amplification'],
                'base_score': 0.7
            },
            'intrusion': {
                'keywords': ['intrusion', 'unauthorized', 'breach', 'compromise'],
                'base_score': 0.8
            },
            'suspicious': {
                'keywords': ['suspicious', 'anomaly', 'unusual', 'abnormal'],
                'base_score': 0.5
            }
        }
    
    def calculate_pattern_score(self, event: Dict[str, Any]) -> float:
        """Calculate pattern matching score based on event content"""
        message = str(event.get('message', '') or event.get('signature', '')).lower()
        
        max_score = 0.0
        for pattern_type, pattern_data in self.threat_patterns.items():
            for keyword in pattern_data['keywords']:
                if keyword in message:
                    max_score = max(max_score, pattern_data['base_score'])
        
        return max_score
    
    def calculate_context_relevance(self, event: Dict[str, Any]) -> float:
        """
        Calculate context relevance score.
        Considers source, classification, and event metadata.
        """
        score = 0.5  # Base score
        
        # Source weighting
        source = event.get('source', '')
        source_weights = {
            'snort': 1.0,
            'suricata': 1.0,
            'zeek': 0.9
        }
        source_weight = source_weights.get(source, 0.8)
        
        # Priority/severity from source
        priority = event.get('priority', 3)
        severity = event.get('severity', 3)
        
        # Lower priority number = higher severity in SNORT (1 is critical)
        if priority <= 1 or severity <= 1:
            score = 0.9
        elif priority == 2 or severity == 2:
            score = 0.7
        elif priority == 3 or severity == 3:
            score = 0.5
        else:
            score = 0.3
        
        # Apply source weight
        score = score * source_weight
        
        return min(score, 1.0)
    
    def calculate_historical_severity(self, event: Dict[str, Any]) -> float:
        """
        Calculate historical severity score.
        In production, this would query historical data.
        For now, uses heuristics.
        """
        # Use signature ID as a proxy for known threats
        signature_id = event.get('signature_id', 0)
        
        # Simulate historical lookup
        # High signature IDs (>1000000) are often less severe
        if signature_id > 0:
            if signature_id < 1000:
                return 0.8  # Well-known critical signatures
            elif signature_id < 10000:
                return 0.6  # Common threats
            else:
                return 0.4  # Less common
        
        return 0.5  # Unknown
    
    def calculate_source_reputation(self, event: Dict[str, Any]) -> float:
        """
        Calculate source IP reputation score.
        In production, would integrate with threat intelligence feeds.
        """
        source_ip = event.get('source_ip', '')
        
        if not source_ip:
            return 0.5
        
        # Heuristic: private IPs are less suspicious from outside
        if source_ip.startswith('10.') or source_ip.startswith('192.168.'):
            return 0.3  # Internal network
        elif source_ip.startswith('172.'):
            return 0.35  # Internal network (RFC 1918)
        else:
            return 0.7  # External source, higher risk
    
    def calculate_anomaly_score(self, event: Dict[str, Any]) -> float:
        """
        Calculate anomaly score based on event characteristics.
        Neural-inspired anomaly detection.
        """
        # Simple heuristic-based anomaly detection
        score = 0.0
        
        # Unusual ports
        dest_port = event.get('destination_port', 0)
        src_port = event.get('source_port', 0)
        
        common_ports = {80, 443, 22, 21, 25, 53, 3306, 5432, 3389}
        if dest_port and dest_port not in common_ports:
            score += 0.3
        
        # Multiple indicators in message
        message = str(event.get('message', '') or event.get('signature', '')).lower()
        indicators = ['attack', 'exploit', 'malicious', 'compromise', 'breach']
        indicator_count = sum(1 for ind in indicators if ind in message)
        score += min(indicator_count * 0.2, 0.5)
        
        return min(score, 1.0)
    
    def calculate_composite_score(self, event: Dict[str, Any]) -> Tuple[float, Dict[str, float]]:
        """
        Calculate composite threat score using weighted components.
        Returns (final_score, component_scores)
        """
        # Calculate individual components
        components = {
            'pattern_match': self.calculate_pattern_score(event),
            'context_relevance': self.calculate_context_relevance(event),
            'historical_severity': self.calculate_historical_severity(event),
            'source_reputation': self.calculate_source_reputation(event),
            'anomaly_score': self.calculate_anomaly_score(event)
        }
        
        # Calculate weighted sum
        final_score = 0.0
        for component, score in components.items():
            weight = self.scoring_weights.get(component, 0.2)
            final_score += score * weight
        
        # Ensure score is in [0, 1]
        final_score = max(0.0, min(1.0, final_score))
        
        return final_score, components
    
    def apply_severity_layers(self, base_score: float) -> Tuple[str, Dict[str, float]]:
        """
        Apply Context Aware Event Severity Layers.
        Returns (severity_level, layer_scores)
        """
        # Layer 1: Primary context layer
        layer1_scores = {
            'critical': self.config.get_severity_threshold('layer1', 'critical'),
            'high': self.config.get_severity_threshold('layer1', 'high'),
            'medium': self.config.get_severity_threshold('layer1', 'medium'),
            'low': self.config.get_severity_threshold('layer1', 'low')
        }
        
        # Layer 2: Secondary risk layer (used for refinement)
        layer2_scores = {
            'critical': self.config.get_severity_threshold('layer2', 'critical'),
            'high': self.config.get_severity_threshold('layer2', 'high'),
            'medium': self.config.get_severity_threshold('layer2', 'medium'),
            'low': self.config.get_severity_threshold('layer2', 'low')
        }
        
        # Determine severity based on both layers
        # Layer 1 is primary, Layer 2 provides confidence adjustment
        if base_score >= layer1_scores['critical']:
            severity = 'critical'
        elif base_score >= layer1_scores['high']:
            severity = 'high'
        elif base_score >= layer1_scores['medium']:
            severity = 'medium'
        else:
            severity = 'low'
        
        # Layer 2 refinement: if score doesn't meet layer2 threshold, downgrade
        if base_score < layer2_scores[severity]:
            # Downgrade one level
            severity_order = ['critical', 'high', 'medium', 'low']
            current_idx = severity_order.index(severity)
            if current_idx < len(severity_order) - 1:
                severity = severity_order[current_idx + 1]
        
        return severity, {'layer1': layer1_scores, 'layer2': layer2_scores}
    
    def score_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main scoring function. Processes event and returns enriched result.
        """
        self.logger.debug(f"Scoring event from {event.get('source', 'unknown')}")
        
        # Calculate composite score
        composite_score, components = self.calculate_composite_score(event)
        
        # Apply severity layers
        severity, layers = self.apply_severity_layers(composite_score)
        
        # Create enriched event
        scored_event = {
            **event,
            'threat_score': round(composite_score, 3),
            'severity': severity,
            'score_components': {k: round(v, 3) for k, v in components.items()},
            'processing_timestamp': datetime.now().isoformat()
        }
        
        self.logger.info(
            f"Event scored: severity={severity}, score={composite_score:.3f}",
            event_id=event.get('signature_id', 'unknown'),
            source=event.get('source', 'unknown')
        )
        
        return scored_event
    
    def score_batch(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Score multiple events"""
        scored_events = []
        for event in events:
            scored_event = self.score_event(event)
            scored_events.append(scored_event)
        
        return scored_events
    
    def prioritize_events(self, scored_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Prioritize events by threat score and severity.
        Returns events sorted by priority (highest first).
        """
        severity_priority = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1
        }
        
        # Sort by severity priority first, then by score
        sorted_events = sorted(
            scored_events,
            key=lambda e: (
                severity_priority.get(e.get('severity', 'low'), 0),
                e.get('threat_score', 0)
            ),
            reverse=True
        )
        
        return sorted_events
