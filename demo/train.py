import pandas as pd
from sklearn.linear_model import LogisticRegression
from consentml import track
from consentml.sources import DataFrameSource

customers = pd.DataFrame({
    "email":   ["alice@example.com", "bob@example.com", "carol@example.com"],
    "tenure":  [14, 3, 27],
    "usage":   [0.8, 0.2, 0.6],
    "churned": [0, 1, 0],
})

def _source():
    return DataFrameSource(customers, subject_id_col="email",
                           label="warehouse.customers")

@track(model_name="churn-risk", source=_source(), db_path="lineage.db")
def train_churn(df):
    return LogisticRegression().fit(df[["tenure", "usage"]], df["churned"])

@track(model_name="ltv-forecast", source=_source(), db_path="lineage.db")
def train_ltv(df):
    return LogisticRegression().fit(df[["tenure", "usage"]], df["churned"])

train_churn()
train_ltv()
print("Trained churn-risk and ltv-forecast; lineage recorded.")
