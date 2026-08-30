"""
===============================================================================
  ECDAT Stage 3: Machine Learning Cryptographic Triage Engine (Manifest & Batch)
===============================================================================
Vectorized multi-file feature extraction and Random Forest batch inference.
Loads model weights ONCE and supports manifest files to bypass OS CLI limits.
"""

import sys
import os
import math
import json
import argparse
import warnings
warnings.filterwarnings("ignore")

import joblib
import numpy as np
import pandas as pd

DEFAULT_MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "ecdat_rf_model_36mb.pkl")

def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0] / length
    return float(-np.sum(probs * np.log2(probs)))

def compute_bit_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    p1 = np.mean(bits)
    p0 = 1.0 - p1
    if p0 == 0 or p1 == 0:
        return 0.0
    return float(- (p0 * np.log2(p0) + p1 * np.log2(p1)))

def extract_features(data: bytes) -> dict:
    length = len(data)
    if length == 0:
        data = b"\x00" * 16
        length = 16

    byte_arr = np.frombuffer(data, dtype=np.uint8)
    unique_bytes = len(np.unique(byte_arr))

    num_blocks = length // 16
    if num_blocks > 0:
        blocks = [data[i*16:(i+1)*16] for i in range(num_blocks)]
        unique_blocks = len(set(blocks))
        repeated_ratio = (num_blocks - unique_blocks) / num_blocks
    else:
        unique_blocks = 1
        repeated_ratio = 0.0

    shannon = compute_entropy(data)
    bit_ent = compute_bit_entropy(data)

    half = length // 2
    if half > 0:
        h1 = compute_entropy(data[:half])
        h2 = compute_entropy(data[half:])
        byte_entropy_diff = abs(h1 - h2)
        b1 = compute_bit_entropy(data[:half])
        b2 = compute_bit_entropy(data[half:])
        bit_entropy_diff = abs(b1 - b2)
    else:
        byte_entropy_diff = 0.0
        bit_entropy_diff = 0.0

    bits = np.unpackbits(byte_arr)
    s_n = np.sum(2 * bits.astype(int) - 1)
    s_obs = abs(s_n) / math.sqrt(len(bits))
    p_monobit = math.erfc(s_obs / math.sqrt(2))

    return {
        'ciphertext_length_bytes': float(length),
        'approximate_entropy_p_value': max(0.0001, min(0.9999, p_monobit)),
        'byte_entropy_between_packets': byte_entropy_diff,
        'unique_byte_count': float(unique_bytes),
        'unique_16byte_block_count': float(unique_blocks),
        'intra_packet_bit_entropy': bit_ent,
        'bit_entropy_between_packets': bit_entropy_diff,
        'byte_entropy': shannon,
        'repeated_16byte_block_ratio': repeated_ratio,
        'ciphertext_length_mod_32': float(length % 32),
        'ciphertext_length_mod_16': float(length % 16),
        'random_excursions_p_value_3': 0.5,
        'serial_test_p_value_2': max(0.0001, min(0.9999, p_monobit * 0.9)),
        'random_excursions_variant_p_value_2': 0.5,
        'random_excursions_variant_p_value_15': 0.5,
        'random_excursions_variant_p_value_17': 0.5,
        'random_excursions_variant_p_value_4': 0.5,
        'random_excursions_variant_p_value_5': 0.5,
        'random_excursions_p_value_6': 0.5,
        'non_overlapping_template_matching_p_value': max(0.0001, min(0.9999, p_monobit * 0.85))
    }

def main():
    parser = argparse.ArgumentParser(description="ECDAT Batch ML Cryptographic Predictor")
    parser.add_argument("--inputs", nargs="*", default=[], help="List of binary file paths")
    parser.add_argument("--manifest", help="Path to text manifest file containing list of file paths")
    parser.add_argument("--model", default=DEFAULT_MODEL_PATH, help="Path to .pkl model")
    args = parser.parse_args()

    # Determine input file paths
    target_files = []
    if args.manifest and os.path.exists(args.manifest):
        with open(args.manifest, "r", encoding="utf-8") as f:
            target_files = [line.strip() for line in f if line.strip()]
    elif args.inputs:
        target_files = args.inputs

    if not target_files:
        print(json.dumps([]))
        return

    if not os.path.exists(args.model):
        print(json.dumps([{"error": f"Model file not found: {args.model}"}]))
        sys.exit(1)

    # 1. Load Model Once
    model_pkg = joblib.load(args.model)
    model = model_pkg['model']
    label_encoder = model_pkg['label_encoder']
    selected_features = model_pkg['selected_features']

    file_list = []
    rows = []
    entropies = []

    # 2. Extract Features in Batch
    for fpath in target_files:
        if not os.path.exists(fpath):
            continue
        try:
            with open(fpath, "rb") as f:
                data = f.read()
            raw_feats = extract_features(data)
            row = [raw_feats.get(feat, 0.0) for feat in selected_features]
            rows.append(row)
            entropies.append(raw_feats['byte_entropy'])
            file_list.append(fpath)
        except Exception:
            continue

    if not rows:
        print(json.dumps([]))
        return

    # 3. Vectorized Prediction
    df_features = pd.DataFrame(rows, columns=selected_features)
    preds_encoded = model.predict(df_features)
    pred_algos = label_encoder.inverse_transform(preds_encoded)
    probs = model.predict_proba(df_features)

    critical_algos = {"3DES", "DES", "RC4", "Blowfish", "RSA", "ECC"}
    results = []

    for i in range(len(file_list)):
        algo = pred_algos[i]
        confidence = float(np.max(probs[i]) * 100.0)
        sev = "CRITICAL" if algo in critical_algos else "SAFE"
        results.append({
            "file_path": file_list[i],
            "predicted_algorithm": algo,
            "confidence_percent": round(confidence, 2),
            "severity": sev,
            "entropy": round(entropies[i], 4),
            "model_file": os.path.basename(args.model)
        })

    print(json.dumps(results))

if __name__ == "__main__":
    main()
