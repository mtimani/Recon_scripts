import collections
import re

def parse_percentage(text):
    # Extract percentage from text
    float_value = float(re.search(r'\d+\.\d+', " 1.54 %").group())
    return float_value

def main():
    owner_percentages = collections.defaultdict(float)

    with open('IP_ranges_and_owners.txt', 'r') as file:
        # Skip the header row
        next(file)
        for line in file:
            ip_range, owner, percentage_text = line.strip().split('|')
            owner_name = owner.strip()
            percentage = parse_percentage(percentage_text)
            owner_percentages[owner_name] += percentage

    # Calculate total percentage
    total_percentage = sum(owner_percentages.values())

    # Display results
    print(f"Total percentage: {total_percentage:.2f}%")
    print("\nOwner Percentages:")

    if total_percentage > 0:
        sorted_owners = sorted(owner_percentages.items(), key=lambda x: x[1], reverse=True)

        for owner_name, percentage in sorted_owners:
            relative_percentage = percentage / total_percentage * 100
            if owner_name == "":
                owner_name = "Empty Name"
            print(f"{owner_name}: {relative_percentage:.2f}%")
    else:
        print("No unique owners found.")

if __name__ == "__main__":
    main()
