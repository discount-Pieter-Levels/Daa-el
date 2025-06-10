import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import networkx as nx
import matplotlib.pyplot as plt
import hashlib

# Step 1: Generate Dummy Access Logs
np.random.seed(42)
users = ['alice', 'bob', 'carol', 'dave', 'eve']
files = ['cust_data.csv', 'salary.xlsx', 'leads.json', 'transactions.db', 'HR_policy.pdf']
methods = ['web', 'ftp', 'sql', 'usb']

data = []
for _ in range(300):
    user = np.random.choice(users)
    file = np.random.choice(files)
    method = np.random.choice(methods)
    hour = np.random.randint(0, 24)
    is_sensitive = file in ['cust_data.csv', 'salary.xlsx', 'transactions.db']
    data.append([user, file, method, hour, is_sensitive])

# Inject Suspicious Activity
for _ in range(5):
    data.append(['eve', 'cust_data.csv', 'usb', 2, True])  # Suspicious

# Step 2: Create DataFrame
log_df = pd.DataFrame(data, columns=['user', 'file', 'method', 'hour', 'is_sensitive'])

# Step 3: Feature Engineering
log_df['is_off_hours'] = log_df['hour'].apply(lambda x: 1 if x < 7 or x > 19 else 0)
log_df['sensitive_access'] = log_df['is_sensitive'].astype(int)

# Step 4: Anomaly Detection with Isolation Forest
features = log_df[['hour', 'is_off_hours', 'sensitive_access']]
model = IsolationForest(contamination=0.02, random_state=42)
log_df['anomaly_score'] = model.fit_predict(features)

# Step 5: Identify Suspicious Users
suspicious_users = log_df[log_df['anomaly_score'] == -1]['user'].value_counts()
print("Suspicious users:\n", suspicious_users)

# Step 6: Build and Visualize Access Graph
G = nx.Graph()
for _, row in log_df.iterrows():
    G.add_edge(row['user'], row['file'])

centrality = nx.betweenness_centrality(G)

# Plot the graph
plt.figure(figsize=(10, 6))
pos = nx.spring_layout(G, seed=42)
node_colors = ['red' if node in suspicious_users.index else 'lightblue' for node in G.nodes()]
nx.draw(G, pos, with_labels=True, node_color=node_colors, node_size=800, font_size=8)
plt.title("User-File Access Graph (Red = Suspicious Users)")
plt.tight_layout()
plt.show()

# Optional: Save suspicious entries to CSV
log_df[log_df['anomaly_score'] == -1].to_csv("suspicious_activity_log.csv", index=False)

file_path = "suspicious_activity_log.csv"

# Read and hash the file
with open(file_path, "rb") as f:
    file_bytes = f.read()
    hash_value = hashlib.sha256(file_bytes).hexdigest()

print("SHA-256 hash of suspicious_activity_log.csv:")
print(hash_value)
