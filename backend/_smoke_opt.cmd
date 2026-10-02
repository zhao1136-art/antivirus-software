@echo off
chcp 65001 >nul
cd /d f:\Caelire\backend
F:\Python314\python.exe -c "import sys; sys.path.insert(0,'.'); from engine.signature_manager import get_signature_manager; sm=get_signature_manager(); print('SigMgr OK total=%s'%sm.get_stats().get('total_signatures')); from engine.yara_scanner import YaraScanner; from config import YARA_RULES_DIR; y=YaraScanner(YARA_RULES_DIR); from engine.local_scanner import LocalScanner; ls=LocalScanner(sm,y); print('LocalScanner OK'); from engine.scheduler import Scheduler; s=Scheduler(); print('Scheduler OK'); from engine.ai_guardian_scanner import get_ai_status; print('AI status', get_ai_status().get('available')); print('SMOKE_TEST_ALL_OK')"
if errorlevel 1 (
  echo SMOKE_TEST_FAILED
  exit /b 1
)
echo SMOKE_TEST_ALL_OK
