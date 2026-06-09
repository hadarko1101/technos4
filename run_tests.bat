@echo off
echo Starting Docker containers...
docker-compose up -d

echo.
echo Starting web server on attacker...
docker exec -d spoof_attacker python server/app.py

echo.
echo Starting spoofing script in a new window...
start "Attacker Script" docker exec -it spoof_attacker python ex4_skeleton.py

echo.
echo Waiting 5 seconds for ARP spoofing to take effect...
timeout /t 5 /nobreak >nul

echo.
echo Testing from Victim...
echo Running dig:
docker exec spoof_victim dig mail.doofle.com +short
echo.
echo Running curl:
docker exec spoof_victim curl -s http://mail.doofle.com
echo.
pause
