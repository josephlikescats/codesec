import asyncio
import importlib.util
from pathlib import Path

root = Path(__file__).resolve().parents[1]
module_path = root / 'src' / 'models' / 'vulnerability_detector.py'
spec = importlib.util.spec_from_file_location('vulnerability_detector', module_path)
detector_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(detector_module)
VulnerabilityDetector = detector_module.VulnerabilityDetector

async def main():
    detector = VulnerabilityDetector()
    await detector.load()
    findings = await detector.detect('user_input = input("id=")\nquery = f"SELECT * FROM users WHERE id = {user_input}"', 'python')
    print('findings count:', len(findings))
    for finding in findings:
        print(f'{finding.id} {finding.title} {finding.severity.value} {finding.confidence}')

if __name__ == '__main__':
    asyncio.run(main())
