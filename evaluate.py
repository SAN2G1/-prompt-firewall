import pandas as pd
import os  # os 모듈 추가
# 1. 모듈 임포트
try:
    from tester_framework.core import Population
    from tester_framework.runners import Stage1LocalRunner
    from tester_framework.orchestrator import Tester
except ImportError:
    print("오류: 'tester_framework' 패키지를 찾을 수 없습니다.")
    print("core.py, runners.py, orchestrator.py가 'tester_framework' 폴더에 있는지 확인하세요.")
    exit()

BENIGN = "benign"
MALICIOUS = "jailbreak"
ALLOW = "ALLOW"
BLOCK = "BLOCK"
ESCALATE = "ESCALATE"


def process_results(results, output_dir):
    """
    테스트 결과를 처리하고 요약 정보를 출력한다. 
    결과를 CSV 파일로 저장한다.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    output_file = os.path.join(output_dir, "evaluation_results.csv")

    summary = {
        "Total Seeds": len(results),
        "TRUE_"+BENIGN: 0,
        "TRUE_"+MALICIOUS: 0,
        "FALSE_"+BENIGN: 0,
        "FALSE_"+MALICIOUS: 0
                }    
    # 결과를 종합한다. pp, fp, fn, tn 등의 통계치를 계산한다.
    for seed in results : 
        if seed.label == BENIGN: # ALLOW , ESCALATE
            if seed.s1_decision == BLOCK:
                summary["FALSE_"+BENIGN] += 1
            else : 
                summary["TRUE_"+BENIGN] += 1
        elif seed.label == MALICIOUS: # BLOCK
            if seed.s1_decision == BLOCK:
                summary["TRUE_"+MALICIOUS] += 1
            else : 
                summary["FALSE_"+MALICIOUS] += 1
    
    return summary

def main():
    # --- 경로 설정 ---
    # 이 스크립트 파일(evaluate.py)의 위치를 기준으로 절대 경로를 만듭니다.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = script_dir  # evaluate.py가 프로젝트 루트에 있으므로
    
    data_path = os.path.join(project_root, "data", "test.csv")
    rules_path = os.path.join(project_root, "stage1_rules.yaml")
    output_dir = os.path.join(project_root, "data") # 결과 파일 저장 경로

    # 1. 데이터 준비 (Population 생성)
    population = Population()
    population.create_population_from_file(data_path)
    
    if len(population) == 0:
        print(f"테스트할 데이터가 없습니다. '{data_path}' 파일을 확인하세요.")
        return

    # 2. 실행 전략 선택 (Runner 생성)
    runner = Stage1LocalRunner()

    # 3. 테스터 생성 (Population과 Runner 주입)
    tester = Tester(population, runner)
    
    # 4. 테스트 실행
    results = tester.run_all()
    summary = process_results(results, output_dir)

    # 5. 결과 출력
    print("\n=== Evaluation Summary ===")
    for key, value in summary.items():
        print(f"{key}: {value}")

 

if __name__ == "__main__":
    main()