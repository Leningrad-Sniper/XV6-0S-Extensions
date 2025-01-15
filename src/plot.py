import matplotlib.pyplot as plt

# Initialize lists for each process to store the queue levels and time (ticks)
ticks = []  # Time (ticks)
process_3 = []  # Queue levels for process 3
process_4 = []  # Queue levels for process 4
process_5 = []  # Queue levels for process 5
process_6 = []  # Queue levels for process 6
process_7 = []  # Queue levels for process 7

# Open and read the log.txt file
with open('log.txt', 'r') as f:
    tick = 0
    for line in f:
        # Split each line into the priority levels for the 5 processes
        priorities = list(map(int, line.strip().split()))
        if len(priorities) == 5:
            # Add the current tick to the ticks list
            ticks.append(tick)

            # Append the priority levels to each process list
            process_3.append(priorities[0])
            process_4.append(priorities[1])
            process_5.append(priorities[2])
            process_6.append(priorities[3])
            process_7.append(priorities[4])

            tick += 1

# Create a line plot for each process
plt.figure(figsize=(10, 6))

plt.plot(ticks, process_3, color='red', label="Process 3 (PID 3)", marker='o', linestyle='-')
plt.plot(ticks, process_4, color='blue', label="Process 4 (PID 4)", marker='x', linestyle='-')
plt.plot(ticks, process_5, color='green', label="Process 5 (PID 5)", marker='^', linestyle='-')
plt.plot(ticks, process_6, color='purple', label="Process 6 (PID 6)", marker='s', linestyle='-')
plt.plot(ticks, process_7, color='orange', label="Process 7 (PID 7)", marker='d', linestyle='-')

# Set labels and title
plt.xlabel('Ticks (Time)')
plt.ylabel('Priority Queue Level')
plt.title('Priority Queue Levels of Processes Over Time (with Priority Boost)')

# Invert y-axis because queue 0 has the highest priority
plt.gca().invert_yaxis()

# Add a legend
plt.legend()

# Show the grid
plt.grid(True)

# Show the plot
plt.show()
