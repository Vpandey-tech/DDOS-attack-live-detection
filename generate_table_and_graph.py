# ==============================================================================
# RESEARCH PAPER: ALL TABLES + ALL GRAPHS GENERATOR
# ==============================================================================
import matplotlib.pyplot as plt
import matplotlib
import numpy as np
import os

matplotlib.rcParams['font.family'] = 'serif'
matplotlib.rcParams['font.serif'] = ['Times New Roman', 'DejaVu Serif']
matplotlib.rcParams['figure.dpi'] = 300
matplotlib.rcParams['savefig.dpi'] = 300

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "research_figures")
os.makedirs(OUT, exist_ok=True)

# === DATA: TABLE 5.1 — Epoch Performance ===
ep = ['Epoch 5', 'Epoch 10', 'Epoch 15', 'Epoch 20', 'Epoch 25']
t1_acc  = [94.9, 99.8, 99.9, 99.9, 99.9]
t1_f1   = [94.6, 99.8, 99.9, 99.9, 99.9]
t1_prec = [92.3, 99.7, 99.8, 99.8, 99.8]
t1_rec  = [97.1, 100.0, 100.0, 100.0, 100.0]
t1_kap  = [0.90, 1.00, 1.00, 1.00, 1.00]
t1_ll   = [0.39, 0.05, 0.01, 0.01, 0.02]

# === DATA: TABLE 5.2 — Comparative ===
cl = ['Proposed\nModel', 'Saurabh\net al. (2024)', 'Kumar &\nSharma (2024)', 'Patel\net al. (2024)', 'Singh &\nGupta (2024)']
cn = ['Proposed Model', 'Saurabh et al.', 'Kumar & Sharma', 'Patel et al.', 'Singh & Gupta']
t2_acc  = [99.22, 96.76, 98.50, 95.00, 94.80]
t2_f1   = [99.23, 95.80, 97.90, 94.99, 93.50]
t2_prec = [98.47, 96.20, 98.10, 95.00, 93.40]
t2_rec  = [100.00, 95.40, 97.80, 94.95, 92.50]
t2_kap  = [0.98, 0.93, 0.97, 0.90, 0.87]
t2_ll   = [0.03, 0.12, 0.05, 0.16, 0.21]
C5 = ['#1B4F72', '#2E86C1', '#27AE60', '#E67E22', '#C0392B']

# ==================== TABLE 5.1 ====================
print("Table 5.1...")
fig, ax = plt.subplots(figsize=(10, 4.2)); ax.axis('off')
ch = ['Parameters'] + ep
rd = [['Accuracy']+[f'{v:.1f}%' for v in t1_acc], ['F1-Score']+[f'{v:.1f}%' for v in t1_f1],
      ['Precision']+[f'{v:.1f}%' for v in t1_prec], ['Recall']+[f'{v:.1f}%' for v in t1_rec],
      ['Kappa']+[f'{v:.2f}' for v in t1_kap], ['LogLoss']+[f'{v:.2f}' for v in t1_ll]]
ax.text(0.5, 0.97, 'Table 5.1 Performance Evaluation of the Proposed Model', transform=ax.transAxes, ha='center', va='top', fontsize=13, fontweight='bold')
t = ax.table(cellText=rd, colLabels=ch, cellLoc='center', loc='center', bbox=[0,0.02,1,0.85])
t.auto_set_font_size(False); t.set_fontsize(10)
for (r,c), cell in t.get_celld().items():
    cell.set_edgecolor('#333'); cell.set_linewidth(0.8)
    if r==0: cell.set_facecolor('#1B4F72'); cell.set_text_props(color='white',fontweight='bold',fontsize=9.5); cell.set_height(0.18)
    elif c==0: cell.set_facecolor('#D6EAF8'); cell.set_text_props(fontweight='bold')
    else: cell.set_facecolor('#FDFEFE')
fig.savefig(os.path.join(OUT,'table_5_1_epoch_performance.png'), bbox_inches='tight', pad_inches=0.3, facecolor='white'); plt.close()
print("  ✅ Done")

# ==================== TABLE 5.2 ====================
print("Table 5.2...")
fig, ax = plt.subplots(figsize=(11, 5.5)); ax.axis('off')
ch2 = ['Parameters'] + cl
rd2 = [['Accuracy']+[f'{v:.2f}%' for v in t2_acc], ['F1-Score']+[f'{v:.2f}%' for v in t2_f1],
       ['Precision']+[f'{v:.2f}%' for v in t2_prec], ['Recall']+[f'{v:.2f}%' for v in t2_rec],
       ['Kappa']+[f'{v:.4f}' for v in t2_kap], ['LogLoss']+[f'{v:.4f}' for v in t2_ll]]
ax.text(0.5, 0.97, 'Table 5.2 Comparative Analysis of Different Models', transform=ax.transAxes, ha='center', va='top', fontsize=13, fontweight='bold')
t2t = ax.table(cellText=rd2, colLabels=ch2, cellLoc='center', loc='center', bbox=[0,0.02,1,0.85])
t2t.auto_set_font_size(False); t2t.set_fontsize(9.5)
for (r,c), cell in t2t.get_celld().items():
    cell.set_edgecolor('#333'); cell.set_linewidth(0.8)
    if r==0: cell.set_facecolor('#1B4F72'); cell.set_text_props(color='white',fontweight='bold',fontsize=8); cell.set_height(0.28)
    elif c==0: cell.set_facecolor('#D6EAF8'); cell.set_text_props(fontweight='bold')
    elif c==1: cell.set_facecolor('#D5F5E3'); cell.set_text_props(fontweight='bold',color='#1B4F72')
    else: cell.set_facecolor('#FDFEFE')
fig.savefig(os.path.join(OUT,'table_5_2_comparative_analysis.png'), bbox_inches='tight', pad_inches=0.3, facecolor='white'); plt.close()
print("  ✅ Done")

# ==================== FIGURE 5.1: EPOCH BAR CHART ====================
print("Fig 5.1 Epoch Performance...")
fig, ax = plt.subplots(figsize=(12, 6.5))
x = np.arange(len(ep))
w = 0.18
metrics_ep = {'Accuracy': t1_acc, 'F1-Score': t1_f1, 'Precision': t1_prec, 'Recall': t1_rec}
colors_bar = ['#1B4F72', '#27AE60', '#E67E22', '#C0392B']
offsets = [-1.5, -0.5, 0.5, 1.5]
for i, (name, vals) in enumerate(metrics_ep.items()):
    bars = ax.bar(x + offsets[i]*w, vals, w, label=name, color=colors_bar[i], edgecolor='white', linewidth=0.8, zorder=3)
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.2, f'{v:.1f}%',
                ha='center', va='bottom', fontsize=7, fontweight='bold', rotation=0)
ax.set_xticks(x); ax.set_xticklabels(ep, fontsize=11, fontweight='bold')
ax.set_ylim(88, 103); ax.set_ylabel('Score (%)', fontsize=12, fontweight='bold')
ax.set_xlabel('Training Epoch', fontsize=12, fontweight='bold')
ax.set_title('Figure 5.1 Performance Evaluation of Proposed Model Across Training Epochs', fontsize=12, fontweight='bold', pad=15)
ax.legend(loc='lower right', fontsize=10, frameon=True, fancybox=True, shadow=True)
ax.grid(axis='y', alpha=0.3, linestyle='--', zorder=0)
ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
plt.tight_layout()
fig.savefig(os.path.join(OUT,'fig_5_1_epoch_performance.png'), bbox_inches='tight', pad_inches=0.2, facecolor='white'); plt.close()
print("  ✅ Done")

# ==================== FIGURE 5.2: KAPPA & LOGLOSS EPOCHS ====================
print("Fig 5.2 Kappa & LogLoss...")
fig, (a1, a2) = plt.subplots(1, 2, figsize=(12, 5))
epochs_x = [5,10,15,20,25]
b1 = a1.bar(ep, t1_kap, color='#1B4F72', edgecolor='white', width=0.5, zorder=3)
for bar, v in zip(b1, t1_kap): a1.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.008, f'{v:.2f}', ha='center', va='bottom', fontsize=10, fontweight='bold')
a1.set_ylim(0.85, 1.06); a1.set_title("Cohen's Kappa Across Epochs", fontsize=12, fontweight='bold')
a1.set_ylabel('Kappa', fontsize=11); a1.grid(axis='y', alpha=0.3, linestyle='--', zorder=0)
a1.spines['top'].set_visible(False); a1.spines['right'].set_visible(False)

b2 = a2.bar(ep, t1_ll, color='#C0392B', edgecolor='white', width=0.5, zorder=3)
for bar, v in zip(b2, t1_ll): a2.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.005, f'{v:.2f}', ha='center', va='bottom', fontsize=10, fontweight='bold')
a2.set_title('LogLoss Across Epochs (Lower is Better)', fontsize=12, fontweight='bold')
a2.set_ylabel('LogLoss', fontsize=11); a2.grid(axis='y', alpha=0.3, linestyle='--', zorder=0)
a2.spines['top'].set_visible(False); a2.spines['right'].set_visible(False)
fig.suptitle('Figure 5.2 Kappa and LogLoss Convergence During Training', fontsize=13, fontweight='bold', y=1.02)
plt.tight_layout()
fig.savefig(os.path.join(OUT,'fig_5_2_kappa_logloss_epochs.png'), bbox_inches='tight', pad_inches=0.2, facecolor='white'); plt.close()
print("  ✅ Done")

# ==================== FIGURES 5.3–5.8: COMPARATIVE BARS ====================
cfgs = [('Accuracy (%)', t2_acc, '5.3', 'fig_5_3_accuracy'), ('F1-Score (%)', t2_f1, '5.4', 'fig_5_4_f1_score'),
        ('Precision (%)', t2_prec, '5.5', 'fig_5_5_precision'), ('Recall (%)', t2_rec, '5.6', 'fig_5_6_recall'),
        ('Kappa', t2_kap, '5.7', 'fig_5_7_kappa'), ('LogLoss', t2_ll, '5.8', 'fig_5_8_logloss')]
for label, vals, fnum, fname in cfgs:
    print(f"Fig {fnum}...")
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(cn, vals, color=C5, edgecolor='white', linewidth=1.2, width=0.6, zorder=3)
    for bar, v in zip(bars, vals):
        fmt = f'{v:.2f}%' if '%' in label else f'{v:.4f}'
        ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+max(vals)*0.015, fmt, ha='center', va='bottom', fontsize=10, fontweight='bold')
    if label == 'LogLoss': ax.set_ylim(0, max(vals)*1.35)
    else: ax.set_ylim(max(0, min(vals)-(max(vals)-min(vals))*0.5), max(vals)*1.08)
    ax.set_ylabel(label, fontsize=12, fontweight='bold')
    mname = label.replace(' (%)','')
    ax.set_title(f'Figure {fnum} Comparative Analysis of {mname}', fontsize=13, fontweight='bold', pad=15)
    ax.grid(axis='y', alpha=0.3, linestyle='--', zorder=0)
    ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
    ax.tick_params(axis='x', labelsize=9)
    bars[0].set_edgecolor('#FFD700'); bars[0].set_linewidth(2.5)
    plt.tight_layout()
    fig.savefig(os.path.join(OUT, f'{fname}.png'), bbox_inches='tight', pad_inches=0.2, facecolor='white'); plt.close()
    print(f"  ✅ Done")

print("\n" + "="*60)
print("🎉 ALL 10 FILES GENERATED SUCCESSFULLY!")
print("="*60)
