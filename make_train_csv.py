import pandas as pd

def main():
    normal = pd.read_csv("out/flows_normal.csv")
    suspicious = pd.read_csv("out/flows_suspicious.csv")

    normal["label"] = 0
    suspicious["label"] = 1

    # Upsample to have more data
    normal = pd.concat([normal] * 5, ignore_index=True)
    suspicious = pd.concat([suspicious] * 5, ignore_index=True)

    df = pd.concat([normal, suspicious], ignore_index=True)

    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    df.to_csv("out/train_flows.csv", index=False)
    print(f"OK: out/train_flows.csv created ({len(df)} rows)")

if __name__ == "__main__":
    main()
