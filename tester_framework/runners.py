# tester_framework/runners.py
from abc import ABC, abstractmethod
from .core import Seed

# 테스트할 필터 로직을 임포트합니다.
try:
    from stage1_filter import Stage1Filter
except ImportError:
    print("Warning: 'filter_logic.stage1_filter'를 찾을 수 없습니다.")
try:
    from stage2_scorer import Stage2Scorer
except ImportError:
    print("Warning: 'filter_logic.stage2_scorer'를 찾을 수 없습니다.")


class IFilterRunner(ABC):
    """
    테스트 실행기 인터페이스 (전략 패턴)
    """
    @abstractmethod
    def run(self, seed: Seed) -> Seed:
        """
        주어진 Seed를 테스트하고, 결과가 업데이트된 Seed 객체를 반환합니다.
        """
        pass

class Stage1LocalRunner(IFilterRunner):
    """
    Stage 1 필터 함수를 실행하는 실행기
    """
    def __init__(self):
        print("Loading Stage 1 Filter in runner...")
        self.filter_instance = Stage1Filter()
        if not self.filter_instance.rules:
            print("Warning: No rules loaded in Stage1Filter.")
        else : 
            print(f"{len(self.filter_instance.rules)} rules loaded successfully in runner.")    
    def run(self, seed: Seed) -> Seed:
        """
        Stage1Filter의 filter_text()를 호출하고 S1 결과를 Seed에 저장합니다.
        """
        try:
            decision, rule_id, msg = self.filter_instance.filter_text(seed.data)
            seed.s1_decision = decision
            seed.s1_rule_id = rule_id
            seed.s1_message = msg
        except Exception as e:
            seed.error = str(e)
            seed.s1_decision = "s1_ERROR"
            
        return seed
    
class Stage2LocalRunner(IFilterRunner):
    """
    Stage 2 스코어러를 실행하는 실행기
    """
    def __init__(self):
        print("Loading Stage 2 Scorer in runner...")
        self.scorer_instance = Stage2Scorer()
        if not self.scorer_instance.models_loaded:
            print("Warning: Models not loaded in Stage2Scorer.")
        else : 
            print("Stage2Scorer models loaded successfully in runner.")    
    def run(self, seed: Seed) -> Seed:
        """
        Stage2Scorer의 predict()를 호출하고 S2 결과를 Seed에 저장합니다.
        """
        try:
            if seed.s1_decision == "ESCALATE":
                decision, risk_score = self.scorer_instance.predict(seed.data)
                seed.s2_decision = decision
                seed.s2_risk_score = risk_score
            else:
                seed.s2_decision = "N/A"
                seed.s2_risk_score = None
        except Exception as e:
            seed.error = str(e)
            seed.s2_decision = "s2_ERROR"
            
        return seed