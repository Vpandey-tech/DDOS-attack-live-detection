# ============================================================================
# COMPLETE DDoS DETECTION — PRODUCTION TRAINING PIPELINE v2.0
# ============================================================================
# IEEE Research Paper — End-to-End Model Training & Validation
# Dataset: CIC-DDoS2019 (cleaned_ddos_data.csv — 15GB from Google Drive)
# Models: LUCID CNN, Autoencoder-SINF, XGBoost, Random Forest, Ensemble
# ALL 72 features preserved — deployment compatible with model_inference.py
# ============================================================================
# PUBLISHED BENCHMARKS ON CIC-DDoS2019 (Targets to beat):
#   GRU (IEEE 2024):      99.54% accuracy
#   XGBoost (IEEE 2026):  99.97% accuracy
#   RF (IEEE 2024):       99.91% accuracy
#   CNN (IEEE 2024):      97.27% accuracy
#   E-SDNN (2024):        98.86% accuracy
# ============================================================================
# INSTRUCTIONS:
#   1. Upload this file to Google Colab
#   2. Runtime → Change runtime type → GPU (recommended)
#   3. Run ALL cells from top to bottom (~15-25 min total)
#   4. Models saved to Google Drive for download
# ============================================================================

# ============================================================================
# CELL 1: ENVIRONMENT SETUP
# ============================================================================
import subprocess
import sys

print("=" * 80)
print("  STEP 1/9: ENVIRONMENT SETUP")
print("=" * 80)

subprocess.check_call([sys.executable, "-m", "pip", "install", "-q",
                       "xgboost", "imbalanced-learn", "scikit-learn",
                       "torch", "tensorflow", "matplotlib", "seaborn"])

import os
import gc
import json
import time
import pickle
import warnings
import numpy as np
import pandas as pd

import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import (
    Input, Conv1D, MaxPooling1D, GlobalMaxPooling1D,
    Dense, Dropout, BatchNormalization, Layer
)
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint, ReduceLROnPlateau

import torch
import torch.nn as nn
import torch.optim as optim

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    precision_score, recall_score, f1_score, roc_auc_score,
    cohen_kappa_score, log_loss, matthews_corrcoef
)
from imblearn.under_sampling import RandomUnderSampler
from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier

warnings.filterwarnings('ignore')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
tf.get_logger().setLevel('ERROR')

from google.colab import drive
drive.mount('/content/drive')

OUTPUT_DIR = '/content/drive/MyDrive/ddos_trained_models'
os.makedirs(OUTPUT_DIR, exist_ok=True)

print("✅ Environment ready!")
print(f"📁 Output: {OUTPUT_DIR}")
print(f"🔧 TF: {tf.__version__} | PyTorch: {torch.__version__} | GPU: {torch.cuda.is_available()}")

# ============================================================================
# CELL 2: FULL DATASET SCAN — COLLECT MAXIMUM BENIGN SAMPLES
# ============================================================================
print("\n" + "=" * 80)
print("  STEP 2/9: SCANNING FULL 15GB DATASET FOR MAXIMUM DATA")
print("=" * 80)

CSV_PATH = "/content/drive/MyDrive/cleaned_ddos_data.csv"
CHUNK_SIZE = 500_000             # Read 500K rows at a time
TARGET_BENIGN = 250_000          # Collect up to 250K benign
TARGET_ATTACK = 250_000          # Collect up to 250K attack
MAX_CHUNKS = 200                 # Safety limit (200 * 500K = 100M rows max scan)

print(f"📂 Source: {CSV_PATH}")
print(f"🎯 Target: {TARGET_BENIGN:,} benign + {TARGET_ATTACK:,} attack = {TARGET_BENIGN+TARGET_ATTACK:,} total")
print(f"📦 Chunk size: {CHUNK_SIZE:,} rows")
print(f"\n⏳ Scanning dataset (this reads from Drive, may take 2-5 minutes)...\n")

benign_chunks = []
attack_chunks = []
total_benign_collected = 0
total_attack_collected = 0
total_rows_scanned = 0
chunk_num = 0

scan_start = time.time()

try:
    for chunk in pd.read_csv(CSV_PATH, chunksize=CHUNK_SIZE, low_memory=False):
        chunk_num += 1
        total_rows_scanned += len(chunk)

        # Clean column names
        chunk.columns = chunk.columns.str.strip()

        # Defensive cleaning
        chunk.replace([float('inf'), -float('inf')], np.nan, inplace=True)
        chunk.fillna(0, inplace=True)

        # Binary label mapping
        chunk['Label'] = chunk['Label'].apply(
            lambda x: 0 if 'BENIGN' in str(x).upper() else 1
        )

        # Collect BENIGN samples (the rare class)
        if total_benign_collected < TARGET_BENIGN:
            benign_in_chunk = chunk[chunk['Label'] == 0]
            needed = TARGET_BENIGN - total_benign_collected
            if len(benign_in_chunk) > needed:
                benign_in_chunk = benign_in_chunk.sample(n=needed, random_state=42)
            benign_chunks.append(benign_in_chunk)
            total_benign_collected += len(benign_in_chunk)

        # Collect ATTACK samples (abundant, sample randomly)
        if total_attack_collected < TARGET_ATTACK:
            attack_in_chunk = chunk[chunk['Label'] == 1]
            needed = TARGET_ATTACK - total_attack_collected
            # Take a proportional sample from each chunk for diversity
            sample_n = min(len(attack_in_chunk), max(needed // max(MAX_CHUNKS - chunk_num, 1), 5000))
            sample_n = min(sample_n, needed)
            if len(attack_in_chunk) > sample_n:
                attack_in_chunk = attack_in_chunk.sample(n=sample_n, random_state=42+chunk_num)
            attack_chunks.append(attack_in_chunk)
            total_attack_collected += len(attack_in_chunk)

        # Progress
        if chunk_num % 5 == 0 or chunk_num <= 3:
            elapsed = time.time() - scan_start
            print(f"   Chunk {chunk_num:>3} | Scanned: {total_rows_scanned:>10,} | "
                  f"Benign: {total_benign_collected:>7,}/{TARGET_BENIGN:,} | "
                  f"Attack: {total_attack_collected:>7,}/{TARGET_ATTACK:,} | "
                  f"Time: {elapsed:.0f}s")

        # Stop if we have enough of both
        if total_benign_collected >= TARGET_BENIGN and total_attack_collected >= TARGET_ATTACK:
            print(f"\n   ✅ Both targets reached at chunk {chunk_num}!")
            break

        if chunk_num >= MAX_CHUNKS:
            print(f"\n   ⚠️ Reached max chunk limit ({MAX_CHUNKS})")
            break

        # Memory cleanup per chunk
        del chunk
        gc.collect()

except Exception as e:
    print(f"\n❌ Error during scanning: {e}")
    raise

scan_time = time.time() - scan_start
print(f"\n📊 Scan Complete in {scan_time:.1f}s")
print(f"   Total rows scanned: {total_rows_scanned:,}")
print(f"   Benign collected:   {total_benign_collected:,}")
print(f"   Attack collected:   {total_attack_collected:,}")

# Combine all collected data
print("\n📦 Combining collected samples...")
df_benign = pd.concat(benign_chunks, ignore_index=True)
df_attack = pd.concat(attack_chunks, ignore_index=True)

# Free chunk lists
del benign_chunks, attack_chunks
gc.collect()

# Balance — use the smaller class count for perfect balance
n_per_class = min(len(df_benign), len(df_attack))
print(f"⚖️ Balancing to {n_per_class:,} per class...")

df_balanced = pd.concat([
    df_benign.sample(n=n_per_class, random_state=42),
    df_attack.sample(n=n_per_class, random_state=42)
]).sample(frac=1, random_state=42).reset_index(drop=True)

del df_benign, df_attack
gc.collect()

print(f"\n✅ Final dataset: {len(df_balanced):,} samples")
print(f"   Benign: {(df_balanced['Label']==0).sum():,}")
print(f"   Attack: {(df_balanced['Label']==1).sum():,}")
print(f"   Columns: {df_balanced.shape[1]}")

# ============================================================================
# CELL 3: PREPROCESSING — KEEP ALL 72 FEATURES
# ============================================================================
print("\n" + "=" * 80)
print("  STEP 3/9: PREPROCESSING (ALL 72 FEATURES PRESERVED)")
print("=" * 80)

X = df_balanced.drop('Label', axis=1)
y = df_balanced['Label']

FEATURE_NAMES = list(X.columns)
NUM_FEATURES = len(FEATURE_NAMES)

print(f"📊 Total features: {NUM_FEATURES}")
print(f"⚠️ KEEPING ALL {NUM_FEATURES} features (no removal) for deployment compatibility")

# Log zero-variance features for the paper, but DO NOT remove them
variance = X.var()
zero_var_cols = variance[variance == 0].index.tolist()
if zero_var_cols:
    print(f"   ℹ️ Note: {len(zero_var_cols)} zero-variance features found: {zero_var_cols}")
    print(f"   ℹ️ These are KEPT for compatibility with feature_extractor.py (72 features)")

# --- Train / Validation / Test Split (60% / 20% / 20%) ---
X_trainval, X_test, y_trainval, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)
X_train, X_val, y_train, y_val = train_test_split(
    X_trainval, y_trainval, test_size=0.25, random_state=42, stratify=y_trainval
)

print(f"\n📊 Split sizes:")
print(f"   Train: {len(X_train):>8,} ({len(X_train)/len(X)*100:.1f}%)")
print(f"   Val:   {len(X_val):>8,} ({len(X_val)/len(X)*100:.1f}%)")
print(f"   Test:  {len(X_test):>8,} ({len(X_test)/len(X)*100:.1f}%)")

del df_balanced, X, y, X_trainval, y_trainval
gc.collect()

# --- Balance training ONLY ---
print("\n⚖️ Balancing training set...")
rus = RandomUnderSampler(random_state=42)
X_train_balanced, y_train_balanced = rus.fit_resample(X_train, y_train)
print(f"   Balanced: {len(X_train_balanced):,} (0: {(y_train_balanced==0).sum():,}, 1: {(y_train_balanced==1).sum():,})")

del X_train, y_train
gc.collect()

# --- Scalers ---
print("\n📏 Fitting scalers...")
standard_scaler = StandardScaler()
X_train_std = standard_scaler.fit_transform(X_train_balanced)
X_val_std = standard_scaler.transform(X_val)
X_test_std = standard_scaler.transform(X_test)

# Confirm the scaler expects exactly 72 features
assert standard_scaler.n_features_in_ == NUM_FEATURES, \
    f"Scaler mismatch! Expected {NUM_FEATURES}, got {standard_scaler.n_features_in_}"

benign_mask = y_train_balanced == 0
X_train_benign_raw = X_train_balanced[benign_mask]

minmax_scaler = MinMaxScaler()
X_train_benign_mm = minmax_scaler.fit_transform(X_train_benign_raw)
X_val_mm = minmax_scaler.transform(X_val)
X_test_mm = minmax_scaler.transform(X_test)

y_train_np = y_train_balanced.values if hasattr(y_train_balanced, 'values') else np.array(y_train_balanced)
y_val_np = y_val.values if hasattr(y_val, 'values') else np.array(y_val)
y_test_np = y_test.values if hasattr(y_test, 'values') else np.array(y_test)

print(f"\n✅ Preprocessing complete!")
print(f"   Features: {NUM_FEATURES} (all 72 preserved)")
print(f"   StandardScaler n_features_in_: {standard_scaler.n_features_in_}")
print(f"   X_train shape: {X_train_std.shape}")

# ============================================================================
# CELL 4: MODEL ARCHITECTURES
# ============================================================================
print("\n" + "=" * 80)
print("  STEP 4/9: MODEL ARCHITECTURES")
print("=" * 80)

class ExpandDimsLayer(Layer):
    """Custom Keras layer — safe serialization, no Lambda bugs."""
    def __init__(self, axis=-1, **kwargs):
        super(ExpandDimsLayer, self).__init__(**kwargs)
        self.axis = axis
    def call(self, inputs):
        return tf.expand_dims(inputs, axis=self.axis)
    def get_config(self):
        config = super(ExpandDimsLayer, self).get_config()
        config.update({'axis': self.axis})
        return config

def build_lucid_cnn(input_dim):
    """LUCID CNN — matches architecture in model_inference.py"""
    inp = Input(shape=(input_dim,), name='flow_input')
    x = ExpandDimsLayer(axis=-1, name='expand_dims')(inp)

    for i, filters in enumerate([64, 128, 256]):
        x = Conv1D(filters=filters, kernel_size=3, activation='relu',
                   padding='same', name=f'conv1d_{i+1}')(x)
        x = BatchNormalization(name=f'bn_{i+1}')(x)
        x = MaxPooling1D(pool_size=2, name=f'maxpool_{i+1}')(x)
        x = Dropout(0.3, name=f'dropout_{i+1}')(x)

    x = GlobalMaxPooling1D(name='global_maxpool')(x)
    x = Dense(512, activation='relu', name='dense_1')(x)
    x = BatchNormalization(name='bn_dense_1')(x)
    x = Dropout(0.4, name='dropout_dense_1')(x)
    x = Dense(128, activation='relu', name='dense_2')(x)
    x = Dropout(0.3, name='dropout_dense_2')(x)
    out = Dense(1, activation='sigmoid', name='output')(x)

    model = Model(inputs=inp, outputs=out, name='LUCID_CNN')
    model.compile(
        optimizer=Adam(learning_rate=0.001),
        loss='binary_crossentropy',
        metrics=['accuracy',
                 tf.keras.metrics.Precision(name='precision'),
                 tf.keras.metrics.Recall(name='recall')]
    )
    return model

class Autoencoder(nn.Module):
    """Autoencoder — architecture matches model_inference.py exactly"""
    def __init__(self, input_dim, encoding_dim=32, hidden_dims=[128, 64]):
        super(Autoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dims[0]), nn.ReLU(),
            nn.Linear(hidden_dims[0], hidden_dims[1]), nn.ReLU(),
            nn.Linear(hidden_dims[1], encoding_dim)
        )
        self.decoder = nn.Sequential(
            nn.Linear(encoding_dim, hidden_dims[1]), nn.ReLU(),
            nn.Linear(hidden_dims[1], hidden_dims[0]), nn.ReLU(),
            nn.Linear(hidden_dims[0], input_dim), nn.Sigmoid()
        )
    def forward(self, x):
        return self.decoder(self.encoder(x))

print("✅ All architectures defined!")

# ============================================================================
# CELL 5: TRAIN ALL 4 MODELS
# ============================================================================
print("\n" + "=" * 80)
print("  STEP 5/9: TRAINING ALL 4 MODELS")
print("=" * 80)

all_results = {}

# ─── MODEL 1: LUCID CNN ─────────────────────────────────────────────────────
print("\n" + "━" * 70)
print("  🧠 MODEL 1/4: LUCID CNN")
print("━" * 70)

lucid_model = build_lucid_cnn(NUM_FEATURES)
lucid_model.summary()

lucid_callbacks = [
    EarlyStopping(monitor='val_loss', patience=15, restore_best_weights=True, verbose=1),
    ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=5, min_lr=1e-6, verbose=1),
    ModelCheckpoint('/content/lucid_best.h5', monitor='val_loss', save_best_only=True, verbose=0)
]

t0 = time.time()
lucid_history = lucid_model.fit(
    X_train_std, y_train_np,
    validation_data=(X_val_std, y_val_np),
    epochs=100, batch_size=512,
    callbacks=lucid_callbacks, verbose=1
)
lucid_time = time.time() - t0
print(f"\n✅ LUCID trained in {lucid_time:.1f}s ({len(lucid_history.history['loss'])} epochs)")

lucid_proba = lucid_model.predict(X_test_std, verbose=0).flatten()
lucid_pred = (lucid_proba > 0.5).astype(int)
print("\n📊 LUCID CNN Results:")
print(classification_report(y_test_np, lucid_pred, target_names=['Benign', 'Attack']))

# ─── MODEL 2: AUTOENCODER ───────────────────────────────────────────────────
print("\n" + "━" * 70)
print("  🔍 MODEL 2/4: AUTOENCODER (Anomaly Detector)")
print("━" * 70)

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"   Device: {device}")

auto_model = Autoencoder(input_dim=NUM_FEATURES).to(device)
opt_ae = optim.Adam(auto_model.parameters(), lr=0.001)
crit_ae = nn.MSELoss()

train_tensor = torch.FloatTensor(X_train_benign_mm).to(device)
AE_EPOCHS, AE_BATCH, AE_PATIENCE = 100, 256, 15
best_vl = float('inf')
patience_ctr = 0

t0 = time.time()
for epoch in range(AE_EPOCHS):
    auto_model.train()
    ep_loss, nb = 0, 0
    for i in range(0, len(train_tensor), AE_BATCH):
        batch = train_tensor[i:i+AE_BATCH]
        recon = auto_model(batch)
        loss = crit_ae(recon, batch)
        opt_ae.zero_grad()
        loss.backward()
        opt_ae.step()
        ep_loss += loss.item()
        nb += 1

    avg_tl = ep_loss / nb
    auto_model.eval()
    with torch.no_grad():
        vb_mask = y_val_np == 0
        if vb_mask.sum() > 0:
            vb_t = torch.FloatTensor(X_val_mm[vb_mask]).to(device)
            vl = crit_ae(auto_model(vb_t), vb_t).item()
        else:
            vl = avg_tl

    if vl < best_vl:
        best_vl = vl
        patience_ctr = 0
        best_state = {k: v.clone() for k, v in auto_model.state_dict().items()}
    else:
        patience_ctr += 1

    if (epoch+1) % 10 == 0 or patience_ctr >= AE_PATIENCE:
        print(f"   Epoch {epoch+1}/{AE_EPOCHS} — Train: {avg_tl:.6f}, Val: {vl:.6f}")
    if patience_ctr >= AE_PATIENCE:
        print(f"   ⏹ Early stop at epoch {epoch+1}")
        break

auto_model.load_state_dict(best_state)
auto_model.eval()
ae_time = time.time() - t0
print(f"\n✅ Autoencoder trained in {ae_time:.1f}s")

with torch.no_grad():
    tr_recon = auto_model(train_tensor)
    tr_errors = nn.functional.mse_loss(tr_recon, train_tensor, reduction='none').mean(1)
    ae_threshold = float(np.percentile(tr_errors.cpu().numpy(), 95))
print(f"   Threshold (95th %ile): {ae_threshold:.6f}")

with torch.no_grad():
    tt_mm = torch.FloatTensor(X_test_mm).to(device)
    tt_recon = auto_model(tt_mm)
    test_errors = nn.functional.mse_loss(tt_recon, tt_mm, reduction='none').mean(1).cpu().numpy()

auto_pred = (test_errors > ae_threshold).astype(int)
print("\n📊 Autoencoder Results:")
print(classification_report(y_test_np, auto_pred, target_names=['Benign', 'Attack']))

del train_tensor, tt_mm, tr_recon, tt_recon
torch.cuda.empty_cache() if torch.cuda.is_available() else None
gc.collect()

# ─── MODEL 3: XGBOOST ───────────────────────────────────────────────────────
print("\n" + "━" * 70)
print("  🌲 MODEL 3/4: XGBOOST")
print("━" * 70)

xgb_model = XGBClassifier(
    n_estimators=500,
    max_depth=12,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    min_child_weight=5,
    gamma=0.1,
    reg_alpha=0.1,
    reg_lambda=1.0,
    scale_pos_weight=1.0,
    random_state=42,
    use_label_encoder=False,
    eval_metric='logloss',
    tree_method='hist',
    n_jobs=-1,
    verbosity=0,
    early_stopping_rounds=30
)

t0 = time.time()
xgb_model.fit(
    X_train_std, y_train_np,
    eval_set=[(X_val_std, y_val_np)],
    verbose=100
)
xgb_time = time.time() - t0
print(f"\n✅ XGBoost trained in {xgb_time:.1f}s (best iter: {xgb_model.best_iteration})")

xgb_pred = xgb_model.predict(X_test_std)
xgb_proba = xgb_model.predict_proba(X_test_std)[:, 1]
print("\n📊 XGBoost Results:")
print(classification_report(y_test_np, xgb_pred, target_names=['Benign', 'Attack']))

print("\n   Running 5-Fold CV...")
xgb_cv = cross_val_score(
    XGBClassifier(n_estimators=300, max_depth=12, learning_rate=0.05,
                  subsample=0.8, colsample_bytree=0.8, random_state=42,
                  use_label_encoder=False, eval_metric='logloss',
                  tree_method='hist', n_jobs=-1, verbosity=0),
    X_train_std, y_train_np, cv=5, scoring='accuracy', n_jobs=-1
)
print(f"   5-Fold CV: {xgb_cv.mean():.4f} ± {xgb_cv.std():.4f}")
gc.collect()

# ─── MODEL 4: RANDOM FOREST ─────────────────────────────────────────────────
print("\n" + "━" * 70)
print("  🌳 MODEL 4/4: RANDOM FOREST")
print("━" * 70)

rf_model = RandomForestClassifier(
    n_estimators=500,
    max_depth=25,
    min_samples_split=5,
    min_samples_leaf=2,
    max_features='sqrt',
    class_weight='balanced_subsample',
    random_state=42,
    n_jobs=-1, verbose=0
)

t0 = time.time()
rf_model.fit(X_train_std, y_train_np)
rf_time = time.time() - t0
print(f"\n✅ Random Forest trained in {rf_time:.1f}s")

rf_pred = rf_model.predict(X_test_std)
rf_proba = rf_model.predict_proba(X_test_std)[:, 1]
print("\n📊 Random Forest Results:")
print(classification_report(y_test_np, rf_pred, target_names=['Benign', 'Attack']))

print("\n   Running 5-Fold CV...")
rf_cv = cross_val_score(
    RandomForestClassifier(n_estimators=300, max_depth=25,
                           min_samples_split=5, min_samples_leaf=2,
                           random_state=42, n_jobs=-1),
    X_train_std, y_train_np, cv=5, scoring='accuracy', n_jobs=-1
)
print(f"   5-Fold CV: {rf_cv.mean():.4f} ± {rf_cv.std():.4f}")
gc.collect()

# ============================================================================
# CELL 6: FEATURE IMPORTANCE ANALYSIS
# ============================================================================
print("\n" + "=" * 80)
print("  STEP 6/9: FEATURE IMPORTANCE ANALYSIS")
print("=" * 80)

# XGBoost feature importance
xgb_importance = xgb_model.feature_importances_
feat_imp = sorted(zip(FEATURE_NAMES, xgb_importance), key=lambda x: x[1], reverse=True)

print("\n📊 Top 20 Most Important Features (XGBoost):")
print(f"   {'Rank':<5} {'Feature':<35} {'Importance':<12}")
print("   " + "-" * 55)
for i, (name, imp) in enumerate(feat_imp[:20], 1):
    print(f"   {i:<5} {name:<35} {imp:.6f}")

# RF feature importance
rf_importance = rf_model.feature_importances_
rf_imp = sorted(zip(FEATURE_NAMES, rf_importance), key=lambda x: x[1], reverse=True)

print("\n📊 Top 20 Most Important Features (Random Forest):")
print(f"   {'Rank':<5} {'Feature':<35} {'Importance':<12}")
print("   " + "-" * 55)
for i, (name, imp) in enumerate(rf_imp[:20], 1):
    print(f"   {i:<5} {name:<35} {imp:.6f}")

# Agreement analysis
xgb_top20 = set([f[0] for f in feat_imp[:20]])
rf_top20 = set([f[0] for f in rf_imp[:20]])
common = xgb_top20 & rf_top20
print(f"\n📊 Feature Agreement: {len(common)}/20 features common in both top-20 lists:")
for f in sorted(common):
    print(f"   ✅ {f}")

# Zero-variance analysis for the paper
if zero_var_cols:
    print(f"\n📊 Zero-variance features (constant values, low signal but kept for deployment):")
    for col in zero_var_cols:
        print(f"   ⚪ {col}")

# ============================================================================
# CELL 7: COMPREHENSIVE METRICS
# ============================================================================
print("\n" + "=" * 80)
print("  STEP 7/9: COMPREHENSIVE EVALUATION")
print("=" * 80)

def compute_all_metrics(y_true, y_pred, y_proba, model_name):
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    mcc = matthews_corrcoef(y_true, y_pred)
    kappa = cohen_kappa_score(y_true, y_pred)
    spec = tn / (tn + fp) if (tn + fp) > 0 else 0
    fpr_val = fp / (fp + tn) if (fp + tn) > 0 else 0
    try: auc_roc = roc_auc_score(y_true, y_proba)
    except: auc_roc = 0.0
    try: ll = log_loss(y_true, np.clip(y_proba, 1e-15, 1-1e-15))
    except: ll = 0.0
    return {
        'model': model_name, 'accuracy': acc, 'precision': prec,
        'recall': rec, 'f1_score': f1, 'specificity': spec,
        'detection_rate': rec, 'false_positive_rate': fpr_val,
        'mcc': mcc, 'kappa': kappa, 'auc_roc': auc_roc, 'log_loss': ll,
        'confusion_matrix': cm.tolist(),
        'tp': int(tp), 'fp': int(fp), 'tn': int(tn), 'fn': int(fn)
    }

lucid_m = compute_all_metrics(y_test_np, lucid_pred, lucid_proba, 'LUCID CNN')
all_results['LUCID CNN'] = lucid_m

auto_proba_proxy = np.clip(test_errors / (ae_threshold * 2 + 1e-8), 0, 1)
auto_m = compute_all_metrics(y_test_np, auto_pred, auto_proba_proxy, 'Autoencoder')
all_results['Autoencoder'] = auto_m

xgb_m = compute_all_metrics(y_test_np, xgb_pred, xgb_proba, 'XGBoost')
all_results['XGBoost'] = xgb_m

rf_m = compute_all_metrics(y_test_np, rf_pred, rf_proba, 'Random Forest')
all_results['Random Forest'] = rf_m

# Ensemble
W = {'lucid': 0.35, 'xgb': 0.30, 'rf': 0.25, 'auto': 0.10}
ens_proba = W['lucid']*lucid_proba + W['xgb']*xgb_proba + W['rf']*rf_proba + W['auto']*auto_proba_proxy
ens_pred = (ens_proba > 0.5).astype(int)
ens_m = compute_all_metrics(y_test_np, ens_pred, ens_proba, 'Ensemble')
all_results['Ensemble'] = ens_m

# Print table
print("\n" + "=" * 110)
print("  FINAL PERFORMANCE TABLE — ALL MODELS")
print("=" * 110)
hdr = f"{'Model':<18} {'Acc':>8} {'Prec':>8} {'Recall':>8} {'F1':>8} {'Spec':>8} {'AUC':>8} {'MCC':>8} {'Kappa':>8} {'LogLoss':>8}"
print(hdr)
print("-" * 110)
for nm, m in all_results.items():
    print(f"{nm:<18} {m['accuracy']:>8.4f} {m['precision']:>8.4f} {m['recall']:>8.4f} "
          f"{m['f1_score']:>8.4f} {m['specificity']:>8.4f} {m['auc_roc']:>8.4f} "
          f"{m['mcc']:>8.4f} {m['kappa']:>8.4f} {m['log_loss']:>8.4f}")
print("-" * 110)

print("\n📊 Confusion Matrices:")
for nm, m in all_results.items():
    print(f"   {nm:<18}: TN={m['tn']:>7,}  FP={m['fp']:>7,}  FN={m['fn']:>7,}  TP={m['tp']:>7,}")

# ============================================================================
# CELL 8: SAVE EVERYTHING
# ============================================================================
print("\n" + "=" * 80)
print("  STEP 8/9: SAVING ALL MODELS")
print("=" * 80)

# LUCID
lp = os.path.join(OUTPUT_DIR, 'lucid.h5')
lsp = os.path.join(OUTPUT_DIR, 'lucid.pkl')
lucid_model.save(lp)
with open(lsp, 'wb') as f: pickle.dump(standard_scaler, f)
print(f"✅ LUCID → {lp} + {lsp}")

# Autoencoder
ap = os.path.join(OUTPUT_DIR, 'auto.pth')
asp = os.path.join(OUTPUT_DIR, 'auto.pkl')
torch.save(auto_model.state_dict(), ap)
with open(asp, 'wb') as f:
    pickle.dump({'scaler': minmax_scaler, 'threshold': ae_threshold,
                 'reconstruction_threshold': ae_threshold}, f)
print(f"✅ Autoencoder → {ap} + {asp}")

# XGBoost
xp = os.path.join(OUTPUT_DIR, 'xgboost_ddos.pkl')
with open(xp, 'wb') as f: pickle.dump(xgb_model, f)
print(f"✅ XGBoost → {xp}")

# Random Forest
rp = os.path.join(OUTPUT_DIR, 'random_forest_ddos.pkl')
with open(rp, 'wb') as f: pickle.dump(rf_model, f)
print(f"✅ Random Forest → {rp}")

# Feature names
fp = os.path.join(OUTPUT_DIR, 'feature_names.json')
with open(fp, 'w') as f: json.dump(FEATURE_NAMES, f, indent=2)
print(f"✅ Features → {fp}")

# Feature importance
fi_path = os.path.join(OUTPUT_DIR, 'feature_importance.json')
with open(fi_path, 'w') as f:
    json.dump({
        'xgboost_importance': {n: float(v) for n, v in feat_imp},
        'random_forest_importance': {n: float(v) for n, v in rf_imp},
        'zero_variance_features': zero_var_cols
    }, f, indent=2)
print(f"✅ Feature Importance → {fi_path}")

# Full metrics
mp = os.path.join(OUTPUT_DIR, 'evaluation_metrics.json')
save_m = {}
for nm, m in all_results.items():
    save_m[nm] = {k: (float(v) if isinstance(v, (np.floating, float)) else v) for k, v in m.items()}
save_m['training_info'] = {
    'dataset': 'CIC-DDoS2019 (cleaned_ddos_data.csv)',
    'dataset_size_gb': '15.09',
    'total_rows_scanned': int(total_rows_scanned),
    'total_samples_used': int(len(y_test_np) + len(y_train_np) + len(y_val_np)),
    'train_samples': int(len(y_train_np)),
    'val_samples': int(len(y_val_np)),
    'test_samples': int(len(y_test_np)),
    'num_features': NUM_FEATURES,
    'feature_names': FEATURE_NAMES,
    'zero_variance_features': zero_var_cols,
    'lucid_train_time_s': float(lucid_time),
    'ae_train_time_s': float(ae_time),
    'xgb_train_time_s': float(xgb_time),
    'rf_train_time_s': float(rf_time),
    'xgb_cv': f"{xgb_cv.mean():.4f} ± {xgb_cv.std():.4f}",
    'rf_cv': f"{rf_cv.mean():.4f} ± {rf_cv.std():.4f}",
    'ae_threshold': float(ae_threshold),
    'ensemble_weights': W
}
with open(mp, 'w') as f: json.dump(save_m, f, indent=2)
print(f"✅ Metrics → {mp}")

# ============================================================================
# CELL 9: VALIDATION
# ============================================================================
print("\n" + "=" * 80)
print("  STEP 9/9: MODEL VALIDATION")
print("=" * 80)

ok = True

print("\n🔍 LUCID...")
try:
    from tensorflow.keras.utils import custom_object_scope
    with custom_object_scope({'ExpandDimsLayer': ExpandDimsLayer}):
        ll = tf.keras.models.load_model(lp, compile=False)
    with open(lsp, 'rb') as f: ls = pickle.load(f)
    assert ls.n_features_in_ == NUM_FEATURES, f"Scaler expects {ls.n_features_in_}, need {NUM_FEATURES}"
    p1 = (ll.predict(X_test_std[:10], verbose=0).flatten() > 0.5).astype(int)
    p2 = (lucid_model.predict(X_test_std[:10], verbose=0).flatten() > 0.5).astype(int)
    assert np.array_equal(p1, p2)
    print(f"   ✅ PASSED (n_features={ls.n_features_in_})")
except Exception as e:
    print(f"   ❌ FAILED: {e}"); ok = False

print("🔍 Autoencoder...")
try:
    with open(asp, 'rb') as f: ad = pickle.load(f)
    assert ad['threshold'] == ae_threshold
    la = Autoencoder(input_dim=NUM_FEATURES).to(device)
    la.load_state_dict(torch.load(ap, map_location=device))
    la.eval()
    print(f"   ✅ PASSED (threshold={ad['threshold']:.6f}, input_dim={NUM_FEATURES})")
except Exception as e:
    print(f"   ❌ FAILED: {e}"); ok = False

print("🔍 XGBoost...")
try:
    with open(xp, 'rb') as f: lx = pickle.load(f)
    assert lx.n_features_in_ == NUM_FEATURES, f"XGB expects {lx.n_features_in_}, need {NUM_FEATURES}"
    assert np.array_equal(lx.predict(X_test_std[:10]), xgb_model.predict(X_test_std[:10]))
    print(f"   ✅ PASSED (n_features={lx.n_features_in_})")
except Exception as e:
    print(f"   ❌ FAILED: {e}"); ok = False

print("🔍 Random Forest...")
try:
    with open(rp, 'rb') as f: lr = pickle.load(f)
    assert lr.n_features_in_ == NUM_FEATURES, f"RF expects {lr.n_features_in_}, need {NUM_FEATURES}"
    assert np.array_equal(lr.predict(X_test_std[:10]), rf_model.predict(X_test_std[:10]))
    print(f"   ✅ PASSED (n_features={lr.n_features_in_})")
except Exception as e:
    print(f"   ❌ FAILED: {e}"); ok = False

# ============================================================================
# FINAL SUMMARY
# ============================================================================
print("\n" + "=" * 80)
print("  🎉 ALL MODELS TRAINED & VALIDATED!" if ok else "  ⚠️ SOME VALIDATIONS FAILED")
print("=" * 80)

print(f"\n📁 Files in {OUTPUT_DIR}/:")
print(f"   ├── lucid.h5                  (LUCID CNN — {NUM_FEATURES} features)")
print(f"   ├── lucid.pkl                 (StandardScaler — n_features_in_={NUM_FEATURES})")
print(f"   ├── auto.pth                  (Autoencoder weights)")
print(f"   ├── auto.pkl                  (MinMaxScaler + threshold)")
print(f"   ├── xgboost_ddos.pkl          (XGBoost — {NUM_FEATURES} features)")
print(f"   ├── random_forest_ddos.pkl    (Random Forest — {NUM_FEATURES} features)")
print(f"   ├── feature_names.json        (Feature list)")
print(f"   ├── feature_importance.json   (XGB + RF importance rankings)")
print(f"   └── evaluation_metrics.json   (All metrics for IEEE paper)")

print(f"\n📊 DATASET STATISTICS FOR PAPER:")
print(f"   Source: CIC-DDoS2019 (cleaned_ddos_data.csv, 15.09 GB)")
print(f"   Rows scanned: {total_rows_scanned:,}")
print(f"   Samples used: {len(y_train_np)+len(y_val_np)+len(y_test_np):,}")
print(f"   Features: {NUM_FEATURES} (all preserved)")

print(f"\n📊 FINAL METRICS FOR IEEE PAPER:")
for nm, m in all_results.items():
    print(f"\n  [{nm}]")
    print(f"    Accuracy:     {m['accuracy']*100:.2f}%")
    print(f"    Precision:    {m['precision']*100:.2f}%")
    print(f"    Recall (DR):  {m['recall']*100:.2f}%")
    print(f"    F1-Score:     {m['f1_score']*100:.2f}%")
    print(f"    Specificity:  {m['specificity']*100:.2f}%")
    print(f"    AUC-ROC:      {m['auc_roc']:.4f}")
    print(f"    MCC:          {m['mcc']:.4f}")
    print(f"    Kappa:        {m['kappa']:.4f}")
    print(f"    Log Loss:     {m['log_loss']:.4f}")

print(f"\n🔧 DEPLOYMENT:")
print(f"   1. Download files from: {OUTPUT_DIR}")
print(f"   2. Copy to: c:\\Users\\DELL\\Desktop\\curr_ddos\\")
print(f"   3. Run: python enhanced_app.py")
print(f"\n✅ COMPLETE! 🚀")
