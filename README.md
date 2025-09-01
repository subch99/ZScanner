# ZScanner Advanced Penetration Testing Framework

Framework canggih untuk pengujian penetrasi dan identifikasi kerentanan keamanan.

## Fitur

- Network reconnaissance dan port scanning
- Deteksi kerentanan SQL Injection
- Deteksi kerentanan XSS
- Deteksi kerentanan LFI/RFI
- Deteksi kerentanan RCE
- Penelitian zero-day
- Fuzzing parameter
- Multi-threading untuk performa tinggi

## Instalasi

```bash
git clone https://github.com/yourusername/zadagpt-pentest-framework.git
cd ZSCanner
pip install -r requirements.txt

cara penggunaan

untuk pencarian canggih
python3 zscanner_ultra.py -a https://<target>

untuk pencarian kerentanan zero day
python3 zscanner_ultra.py -z https://<target>
atau
python3 zscanner_ultra.py -z -a https://<target>
