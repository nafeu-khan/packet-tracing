import os
import csv
import argparse
import re
import matplotlib.pyplot as plt

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Parse network traffic data and display summary information."
    )
    parser.add_argument("-t", "--trigger", action="store_true", help="Trigger data parsing.")
    parser.add_argument("-s", "--start", type=int, required=True, help="Start year.")
    parser.add_argument("-e", "--end", type=int, required=True, help="End year.")
    parser.add_argument("-sm", "--startmonth", type=int, help="Start month (1-12).")
    parser.add_argument("-em", "--endmonth", type=int, help="End month (1-12).")
    parser.add_argument("-sd", "--startday", type=int, help="Start day (1-31).")
    parser.add_argument("-ed", "--endday", type=int, help="End day (1-31).")
    args = parser.parse_args()

    # Validate year, month, and day ranges
    if args.start > args.end:
        parser.error("'start' year cannot be greater than 'end' year.")
    if args.startmonth and not (1 <= args.startmonth <= 12):
        parser.error("'startmonth' must be between 1 and 12.")
    if args.endmonth and not (1 <= args.endmonth <= 12):
        parser.error("'endmonth' must be between 1 and 12.")
    if args.startmonth and args.endmonth and args.startmonth > args.endmonth:
        parser.error("'startmonth' cannot be greater than 'endmonth'.")
    if args.startday and not (1 <= args.startday <= 31):
        parser.error("'startday' must be between 1 and 31.")
    if args.endday and not (1 <= args.endday <= 31):
        parser.error("'endday' must be between 1 and 31.")
    if args.startday and args.endday and args.startday > args.endday:
        parser.error("'startday' cannot be greater than 'endday'.")

    return args

def walk_extracted_data(data_path, start_year, end_year, start_month=0, end_month=0, start_day=0, end_day=0):
    data_summary = {}

    for year in range(start_year, end_year + 1):
        year_path = os.path.join(data_path, str(year))
        if not os.path.exists(year_path):
            print(f"Year path not found: {year_path}")
            continue

        for month in range(1, 13):
            if start_month and end_month and (month < start_month or month > end_month):
                continue
            month_path = os.path.join(year_path, f"{month:02d}")
            if not os.path.exists(month_path):
                print(month_path + " not found")
                continue

            for day in os.listdir(month_path):  # Iterate over day directories
                if not day.isdigit():
                    print(day + " is not a valid day directory")
                    continue
                day_int = int(day)
                if start_day and end_day and (day_int < start_day or day_int > end_day):
                    print(f"Skipping day {day_int}")
                    continue
                day_path = os.path.join(month_path, f"{day_int:02d}")
                if not os.path.isdir(day_path):
                    print(day_path + " not found")
                    continue

                # Determine the key based on the desired granularity
                key = f"{year}-{month:02d}-{day_int:02d}" if start_day else f"{year}-{month:02d}" if start_month else str(year)

                # Initialize the aggregation key if not present
                if key not in data_summary:
                    data_summary[key] = {
                        "Total Traces": 0,
                        "Total Packets": 0,
                        "Total Trace Size (GB)": 0.0,
                        "Total Transferred Bytes (TB)": 0.0,
                        "Total IP Packets": 0,
                        "Total IP6 Packets": 0,
                    }

                # Process each file
                for file in os.listdir(day_path):
                    print(day_path,"====",data_summary[key]["Total Traces"])
                    if file.endswith(".csv"):
                        file_path = os.path.join(day_path, file)
                        try:
                            with open(file_path, "r") as csv_file:
                                reader = csv.DictReader(csv_file)
                                for row in reader:
                                    if re.match(r"\d*-total\.csv", file):
                                        data_summary[key]["Total Trace Size (GB)"] += float(row.get("FileSize(MB)", 0.0) or 0.0) / 1024
                                        data_summary[key]["Total Packets"] += int(row.get("packets", 0) or 0)
                                        data_summary[key]["Total Transferred Bytes (TB)"] += int(row.get("bytes", 0) or 0) / (1024**4)
                                    protocol = row.get("Protocol", "")
                                    if protocol.startswith("ip-packets"):
                                        data_summary[key]["Total IP Packets"] += int(row.get("packets", 0) or 0)
                                    elif protocol.startswith("ip6-packets"):
                                        data_summary[key]["Total IP6 Packets"] += int(row.get("packets", 0) or 0)
                        except Exception as e:
                            print(f"Error processing file {file_path}: {e}")
                data_summary[key]["Total Traces"] += 1
    print(data_summary)

    return data_summary

def plot_data(data_summary, level):
    # Ensure the output directory exists
    output_dir = "mawi_graphs"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Extract x-axis (keys) and y-axis (values) data
    x_axis = list(data_summary.keys())  # Keys like '2023', '2023-11', '2023-11-01'

    # Prepare the statistics to plot
    stats = ["Total Traces", "Total Packets", "Total Trace Size (GB)",
             "Total Transferred Bytes (TB)", "Total IP Packets", "Total IP6 Packets"]

    plt.figure(figsize=(12, 8))
    drawable_stats=["Total IP Packets", "Total IP6 Packets"]
    # Plot each statistic as a separate line
    for stat in drawable_stats:
        y_axis = [data_summary[key][stat] for key in x_axis]
        plt.plot(x_axis, y_axis, marker="o", label=stat)  # Add a line for each stat

    # Configure the graph
    plt.title(f"Network Traffic Statistics over {level.capitalize()}s")
    plt.xlabel(f"{level.capitalize()}s")
    plt.ylabel("Values")
    plt.xticks(rotation=45)
    plt.legend()  # Add a legend for clarity
    plt.grid()
    plt.tight_layout()

    # Save the combined plot
    file_name = os.path.join(output_dir, f"combined_statistics_over_{level}.png")
    plt.savefig(file_name)
    plt.close()
    print(f"Saved combined graph: {file_name}")

def main():
    args = parse_arguments()

    if args.trigger:
        data_path = "extracted_data"  # Base directory for the data
        print("\nParsing network traffic data...\n")
        print(args.start," ",args.end," ",args.startmonth," ",args.endmonth," ",args.startday," ",args.endday)
        data_summary = walk_extracted_data(
            data_path, 
            args.start, 
            args.end, 
            args.startmonth, 
            args.endmonth, 
            args.startday, 
            args.endday
        )

        # Determine the level (Year, Month, or Day)
        level = "day" if args.startday or args.endday else "month" if args.startmonth or args.endmonth else "year"

        # Print and plot the summarized data
        if data_summary:
            print("\nSummary Information:")
            for entry in data_summary:
                print(entry)
            plot_data(data_summary, level)
        else:
            print("No data found to process.")
    else:
        print("Use -t or --trigger flag to start parsing.")

if __name__ == "__main__":
    main()
