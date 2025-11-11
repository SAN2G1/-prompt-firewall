import pandas as pd
import os  # os 모듈 추가
# 1. 모듈 임포트
try:
    from tester_framework.core import Population
    from tester_framework.runners import Stage1LocalRunner, Stage2LocalRunner
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


def process_results(results, output_dir, stage_name):
    """
    테스트 결과를 처리하고 요약 정보를 출력한다.
    결과를 CSV 파일로 저장한다.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    output_file = os.path.join(output_dir, f"evaluation_results_{stage_name}.csv")

    summary = {
        "Total Seeds": len(results),
        "PASS_" + BENIGN: 0,
        "PASS_" + MALICIOUS: 0,
        "BLOCK_" + BENIGN: 0,
        "BLOCK_" + MALICIOUS: 0
    }

    decision_attr = ""
    if stage_name == "s1":
        decision_attr = "s1_decision"
    elif stage_name == "s2":
        decision_attr = "s2_decision"
    else:
        raise ValueError("stage_name은 's1' 또는 's2'여야 합니다.")

    # 결과를 종합한다.
    for seed in results:
        # getattr을 사용하여 동적으로 s1_decision 또는 s2_decision 값을 가져옵니다.
        check_decision = getattr(seed, decision_attr, None)

        if seed.label == BENIGN:
            if check_decision == BLOCK:
                summary["BLOCK_" + BENIGN] += 1
            else:
                summary["PASS_" + BENIGN] += 1
        elif seed.label == MALICIOUS:
            if check_decision == BLOCK:
                summary["BLOCK_" + MALICIOUS] += 1
            else:
                summary["PASS_" + MALICIOUS] += 1

    return summary


def main():
    # --- 경로 설정 ---
    # 이 스크립트 파일(evaluate.py)의 위치를 기준으로 절대 경로를 만듭니다.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = script_dir  # evaluate.py가 프로젝트 루트에 있으므로

    data_path = os.path.join(project_root, "data", "test.csv")
    rules_path = os.path.join(project_root, "stage1_rules.yaml")
    output_dir = os.path.join(project_root, "data")  # 결과 파일 저장 경로

    # 1. 데이터 준비 (Population 생성)
    population = Population()
    population.create_population_from_file(data_path)

    if len(population) == 0:
        print(f"테스트할 데이터가 없습니다. '{data_path}' 파일을 확인하세요.")
        return

    # 2. 실행 전략 선택 (Runner 생성)
    runner_s1 = Stage1LocalRunner()
    runner_s2 = Stage2LocalRunner()

    # 3. s1_테스터 생성 (Population과 Runner 주입)
    tester_s1 = Tester(population, runner_s1)

    # 4. s1_테스트 실행
    print("--- Running Stage 1 ---")
    results_s1 = tester_s1.run_all()
    summary_s1 = process_results(results_s1, output_dir, "s1")

    # S1에서 ESCALATE된 Seed만 필터링
    escalated_seeds = [seed for seed in results_s1 if seed.s1_decision == ESCALATE]
    
    # 만약 ESCALATE된 데이터가 없다면 Stage 2를 실행하지 않고 종료
    if not escalated_seeds:
        print("\n--- No seeds escalated to Stage 2 ---")
        summary_s2 = {}
    else:
        escalated_population = Population(seeds=escalated_seeds)

        # 3. s2_테스터 생성 (필터링된 Population과 Runner 주입)
        tester_s2 = Tester(escalated_population, runner_s2)
        
        # 4. s2_테스트 실행
        print(f"\n--- Running Stage 2 on {len(escalated_seeds)} escalated seeds ---")
        results_s2 = tester_s2.run_all()
        summary_s2 = process_results(results_s2, output_dir, "s2")

    # 5. 결과 출력
    print("\n=== Evaluation Summary S1 ===")
    for key, value in summary_s1.items():
        print(f"{key}: {value}")
    print("==========================")
    
    if summary_s2:
        print("\n=== Evaluation Summary S2 ===")
        for key, value in summary_s2.items():
            print(f"{key}: {value}")
        print("==========================")

    

if __name__ == "__main__":
    main()