class ACEScorer:
    def __init__(self):
        # Weights defined in your Concept Note [cite: 32, 34]
        self.weights = {
            "base": 0.30,
            "dcs": 0.20,
            "ass": 0.18,
            "ecp": 0.22,
            "bli": 0.20
        }

    def calculate(self, base_cvss, dcs, ass, ecp, bli):
        """
        Computes ACE Index normalized to [0, 10] [cite: 30, 34]
        """
        score = (base_cvss * self.weights['base']) + \
                (dcs * self.weights['dcs']) + \
                (ass * self.weights['ass']) + \
                (ecp * self.weights['ecp']) + \
                (bli * self.weights['bli'])
        
        return round(min(score, 10.0), 2)

    def get_priority_band(self, score):
        # Implementation of ACE Priority Bands [cite: 36]
        if score >= 8.5: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 5.0: return "MEDIUM"
        return "LOW"
