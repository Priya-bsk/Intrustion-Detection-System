#  Intrusion Detection System (IDS)  
*Hybrid IDS using Signature-based + Anomaly-based Detection*  
 Random Forest Classifier 

---

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/ML-RandomForest-green?logo=scikit-learn" />
 

</p>


---

## Project Overview  

This project implements a *hybrid Intrusion Detection System (IDS)* with two integrated components:  

🔹 *Signature-based detection* → Identifies *known attacks* via rule-based matching.  
🔹 *Anomaly-based detection (Random Forest)* → Detects *unknown threats* with *99.87% accuracy*.  

Both modules run *separately* but complement each other, providing *real-time monitoring dashboards* and rich visualizations.  

---

##  Features  

✔ *Signature-based packet inspection & rule alerts*  
✔ *Anomaly-based detection with Random Forest ML model*  
✔ *Real-time dashboards & visualization*  
✔ *Traffic statistics: Anomaly vs Normal*  
✔ *Easy-to-run modular design*  

---

## 🖥 Dashboards & Visualizations  

*Signature-based Intrusion Detection Logs* 
<img width="1558" height="883" alt="image" src="https://github.com/user-attachments/assets/21d0c454-5b94-44d8-ba36-eb6cc524d417" />

 *Real-Time IDS Anomaly Dashboard*
<img width="671" height="528" alt="image" src="https://github.com/user-attachments/assets/04f3a67c-1236-46ed-b88f-5d1d4c42c111" />

 *Anomaly Detection Over Time* 
<img width="692" height="320" alt="image" src="https://github.com/user-attachments/assets/3e270830-e59b-49ca-9aed-bab15a4c61bf" />

 *Anomaly Count vs Normal Traffic*  
<img width="738" height="520" alt="image" src="https://github.com/user-attachments/assets/e2b79585-5c5a-40f7-af81-6bc790f09339" />

*Detected Anomalies with Probability*  
<img width="704" height="471" alt="image" src="https://github.com/user-attachments/assets/e846b080-49c9-4136-8239-d1be427e45ac" />

---

## 📊 Model Performance  

- *Algorithm:* Random Forest Classifier 
- *Accuracy:* *99.87%*  
- *Dataset:* [Specify dataset → NSL-KDD / CICIDS]  
- *Metrics:* Precision, Recall, F1-score  


---

## 🚀 Installation & Usage  

```bash
# 1️⃣ Clone Repository
git clone https://github.com/yourusername/Intrusion-detection-system.git
cd intrusion-detection

# 2️⃣ Install Dependencies
pip install -r requirements.txt

# 3️⃣ Run Signature-based IDS
cd signature
python main.py

# 4️⃣ Run Anomaly-based IDS
cd anomaly
python detect_anomalies.py 
