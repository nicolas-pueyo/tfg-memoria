# rag_client.py
from typing import List, Dict
from opencti.client import ApiClient

"""
Cliente que utiliza el cliente de OpenCTI para hacer las búsquedas necesarias para el RAG
"""
class OpenCTIRAGClient:
    def __init__(self):
        self.client = ApiClient().api



    def find_indicators_by_value(self, value: str) -> List[Dict]:
        return self.client.indicator.list(
            search=value,
            first=20,
        )

    def find_indicators_by_pattern(self, value: str) -> List[Dict]:
        indicators = self.find_indicators_by_value(value)

        return [
            i for i in indicators
            if i.get("pattern") and value in i["pattern"]
        ]


    def get_indicator_relationships(self, indicator_id: str) -> List[Dict]:
        return self.client.stix_core_relationship.list(
            fromId=indicator_id,
            first=50,
        )


    def find_reports_mentioning(self, value: str) -> List[Dict]:
        return self.client.report.list(
            search=value,
            first=10,
        )
