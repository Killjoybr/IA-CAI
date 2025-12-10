from typing import List, Dict, Tuple
import numpy as np
from sklearn.linear_model import LogisticRegression


class SeverityModel:
    """
    Modelo muito simples para estimar severidade (0=baixo, 1=médio, 2=alto).
    Os dados são sintéticos, baseados em heurística,
    mas o pipeline é real (features -> modelo sklearn -> previsão).
    """

    def __init__(self):
        self.model = LogisticRegression(multi_class="multinomial", max_iter=500)
        self._train_synthetic()

    @staticmethod
    def _encode_type(finding_type: str) -> int:
        mapping = {
            "xss_reflected": 2,
            "sqli_error_based": 2,
            "missing_header": 1,
        }
        return mapping.get(finding_type, 0)

    @staticmethod
    def _encode_header_name(header: str) -> int:
        if header is None:
            return 0
        header = header.lower()
        if "content-security-policy" in header:
            return 2
        if "strict-transport-security" in header:
            return 2
        if "x-frame-options" in header:
            return 1
        if "x-content-type-options" in header:
            return 1
        return 0

    def _features_from_finding(self, f: Dict) -> List[float]:
        """
        Extrai um vetor de features numéricas para o modelo.
        Exemplo de features:
          - tipo codificado
          - se tem payload
          - se é header crítico
          - tamanho da URL normalizado
        """
        f_type = self._encode_type(f.get("type", ""))
        has_payload = 1 if f.get("payload") else 0
        header_score = self._encode_header_name(f.get("header"))
        url_len = len(f.get("url", "")) if f.get("url") else 0
        url_len_norm = min(url_len / 200.0, 1.0)

        return [f_type, has_payload, header_score, url_len_norm]

    def _train_synthetic(self):
        """
        Cria um dataset sintético pequeno apenas para ter pesos "aprendidos".
        """
        X = []
        y = []

        # alguns exemplos "manuais"
        examples: List[Tuple[Dict, int]] = [
            ({"type": "xss_reflected", "payload": "p", "url": "http://a"}, 2),
            ({"type": "sqli_error_based", "payload": "p", "url": "http://a"}, 2),
            ({"type": "missing_header", "header": "content-security-policy", "url": "http://a"}, 1),
            ({"type": "missing_header", "header": "x-frame-options", "url": "http://a"}, 1),
            ({"type": "missing_header", "header": "strict-transport-security", "url": "http://a"}, 2),
            ({"type": "missing_header", "header": "x-content-type-options", "url": "http://a"}, 1),
            ({"type": "other", "url": "http://a"}, 0),
        ]

        for f, sev in examples:
            X.append(self._features_from_finding(f))
            y.append(sev)

        X = np.array(X)
        y = np.array(y)

        self.model.fit(X, y)

    def predict_severity(self, finding: Dict) -> Tuple[int, float]:
        """
        Retorna (classe, probabilidade da classe).
        Classe: 0=baixo, 1=médio, 2=alto.
        """
        x = np.array([self._features_from_finding(finding)])
        probs = self.model.predict_proba(x)[0]
        cls = int(np.argmax(probs))
        conf = float(probs[cls])
        return cls, conf

    @staticmethod
    def label_from_class(cls: int) -> str:
        mapping = {0: "baixo", 1: "médio", 2: "alto"}
        return mapping.get(cls, "desconhecido")
