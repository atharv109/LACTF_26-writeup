# flag irl

**Category:** misc

---

#### Description

A video of a 3D printer printing a text nameplate is provided. The flag is the text being printed, which must be recovered by tracking the printer's motion.

#### Solution

The key insight is that on the **top layers** of a 3D-printed text nameplate, the print head only visits positions where the raised letters exist. By tracking the head's X position (physical X axis) and the bed's X position in the video frame (which maps to the physical Y axis due to the side-on camera angle), we can reconstruct a 2D map of the printed text.

**Step 1: Position tracking (pre-existing)**

The 1080p video (`video1080p.mp4`, 60fps, 29168 frames) had already been processed with template-matching trackers to produce:

* `pos_1080.npy` — head/nozzle (X, Y) pixel position per frame
* `bed_pos_1080.npy` — bed reference point (X, Y, confidence) per frame

The head X tracks the physical X axis (head moves left/right). The bed X tracks the physical Y axis (bed moves forward/backward, appearing as horizontal motion from the camera's oblique angle).

**Step 2: Identify the text-printing region**

During base layers (frames 0–\~26000), the head sweeps the full width uniformly (rectangular infill). During the top/text layers (frames \~26100–28350), the head only visits positions where letters exist, producing variable-width sweeps. After \~28400 the head parks at home position.

**Step 3: Reconstruct the 2D print path**

Plot head X vs bed X for the text-layer frames, filtering out fast travel moves (speed > 2 px/frame) to keep only slow printing moves. The resulting 2D histogram reveals the letter shapes.

```python
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from scipy.ndimage import gaussian_filter1d, gaussian_filter
import cv2

OUT = 'samples'

head = np.load(f'{OUT}/pos_1080.npy').astype(float)
bed = np.load(f'{OUT}/bed_pos_1080.npy')

hx = head[:, 0]  # head X = physical X (head moves left/right)
bx = bed[:, 0]   # bed X in video = physical Y (bed moves forward/back)

# Text layer region
s, e = 26100, 28350
hx_seg = gaussian_filter1d(hx[s:e], sigma=1)
bx_seg = gaussian_filter1d(bx[s:e], sigma=1)

# Compute per-frame speed, filter to slow (printing) moves only
dx = np.diff(hx_seg)
dy = np.diff(bx_seg)
speed = np.sqrt(dx**2 + dy**2)
speed = np.append(speed, 0)
mask = speed < 2.0

# Build 2D histogram (head X vs bed X)
x_min, x_max = 975, 1295
y_min, y_max = 1510, 1645
bins_x = int(x_max - x_min)
bins_y = int((y_max - y_min) * 2)  # 2x oversample Y for resolution

hist, _, _ = np.histogram2d(
    hx_seg[mask], bx_seg[mask],
    bins=[bins_x, bins_y],
    range=[[x_min, x_max], [y_min, y_max]]
)

# Render as image (transpose to get rows=Y, cols=X)
img = hist.T

# Crop to text bounding box
mask2 = img > 0
rows = np.any(mask2, axis=1)
cols = np.any(mask2, axis=0)
rmin, rmax = np.where(rows)[0][[0, -1]]
cmin, cmax = np.where(cols)[0][[0, -1]]
cropped = img[max(0, rmin - 2):rmax + 2, max(0, cmin - 2):cmax + 2]

# Scale up and smooth for readability
h, w = cropped.shape
big = cv2.resize(cropped.astype(np.float32), (w * 8, h * 8),
                 interpolation=cv2.INTER_LINEAR)
smooth = gaussian_filter(big, sigma=2.5)

plt.figure(figsize=(30, 15))
plt.imshow(smooth, cmap='hot', interpolation='bilinear', aspect='equal')
plt.axis('off')
plt.tight_layout()
plt.savefig('flag_text.png', dpi=200, bbox_inches='tight')
plt.close()
```

The resulting heatmap shows three rows of text. At this resolution the font renders `f` like `P`, `g`/`e` like `G`, and `}` like `3`, but the text is readable:

```
4n_irl_fla
6_f0r_onc3
}
```

Prepending the `lactf{` prefix (from Row 1, which is faintest due to fewer data points at the start of the text layer):

#### Flag

```
lactf{4n_irl_fla6_f0r_onc3}
```
