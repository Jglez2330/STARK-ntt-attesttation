import numpy as np
import matplotlib.pyplot as plt

# Generate sampled points only
sample_points = np.linspace(0, 2 * np.pi, 10)
sample_values = np.sin(sample_points)

# Plot only sampled points without labels
plt.scatter(sample_points, sample_values, color='red', zorder=5)

# Add title and grid only
plt.title("Points")
plt.grid(True)
if __name__ == "__main__":
    plt.show()
