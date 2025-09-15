import subprocess

print("Starting Intrusion Detection System...")

subprocess.Popen(["python", "packet_capture.py"])
subprocess.Popen(["python", "signature.py"])
subprocess.Popen(["python", "flask_server.py"]) 
