## AWS Logging & Monitoring Lab

Implemented proactive threat detection and compliance monitoring across AWS services using CloudTrail, GuardDuty, AWS Config, CloudWatch, and Athena for log analysis.

---

## Table of Contents

- [Overview]
- [Real-World Risk]
- [What I Built]
- [Diagram]
- [Objectives]
- [Steps Performed]
  - [1. CloudTrail Setup]
  - [2. GuardDuty Enablement]
  - [3. AWS Config Setup and Rules]
  - [4. CloudWatch Metric Filter & Alarm]
  - [5. Athena Log Query Setup]
  - [6. Cleanup]
- [Screenshots]
- [JSONs Table]
- [Lessons Learned]
- [References]

---

## Overview

This lab focused on implementing centralized security logging, threat detection, and configuration compliance monitoring in AWS. Using CloudTrail for API auditing, GuardDuty for threat detection, AWS Config for resource compliance, CloudWatch for alerting, and Athena for querying logs, the lab demonstrates an end-to-end logging and monitoring pipeline essential for security operations.

---

## Real-World Risk

In modern cloud environments, the sheer volume of API activity and complex configurations can obscure malicious behavior or compliance drift, increasing the risk of unnoticed breaches and misconfigurations. Without centralized logging, threat detection and continuous compliance monitoring, attackers can exploit gaps in visibility to move laterally, exfiltrate data or persist undetected. This lab addresses these risks by implementing a comprehensive logging and monitoring solution that enables proactive detection of suspicious activities and ensures that cloud resources remain securely configured.

---

## What I Built

- Multi-region AWS CloudTrail trail to capture all API calls and user activity.
- Enabled GuardDuty for continuous threat detection using machine learning and threat intelligence.
- Configured AWS Config with multiple managed rules to monitor resource compliance against security best practices.
- Created CloudWatch metric filters and alarms to detect and alert on critical events such as unauthorized console logins.
- Set up Athena to query CloudTrail logs stored in S3 for detailed forensic analysis and incident investigation.
- Secured log storage and alerting mechanisms to ensure integrity and timeliness of security data.

---

## Diagram

![AWS Security Lab Architecture](diagram.png)

---

## Objectives

- Enable CloudTrail to log all API activity across regions into S3.
- Enable GuardDuty threat detection.
- Set up AWS Config with managed rules for security compliance.
- Configure CloudWatch metric filters and alarms for security events.
- Use Athena to query CloudTrail logs for audit and investigation.

---

## Steps Performed

1. CloudTrail Setup
   - Created a multi-region CloudTrail trail named main-trail.
   - Configured logs to be delivered to a dedicated S3 bucket (my-cloudtrail-logs-sebastiansilva).
   - Enabled optional CloudWatch Logs integration.
   - Verified logging via CloudTrail console and S3 bucket contents.
   - Collected sample JSON event logs for documentation.

2. GuardDuty Enablement
   - Enabled GuardDuty in the main AWS region.
   - Verified GuardDuty status via console screenshots.
   - Noted that sample findings were not generated in the environment due to AWS timing but included a sample finding JSON in documentation.

3. AWS Config Setup and Rules
   - Enabled AWS Config recording for all supported resource types.
   - Created multiple AWS managed rules focusing on security best practices, including:
      - restricted-ssh
      - s3-bucket-public-read-prohibited
      - s3-bucket-public-write-prohibited
      - ec2-instance-no-public-ip
      - iam-password-policy
      - root-account-mfa-enabled
      - cloudtrail-enabled
      - guardduty-enabled-centralized
   - Collected compliance dashboard and non-compliance example screenshots.

4. CloudWatch Metric Filter & Alarm
   - Created a metric filter on CloudTrail logs for detecting ConsoleLogin events.
   - Created a CloudWatch alarm triggered when login events occur.
   - Captured metric filter and alarm summary screenshots.

5. Athena Log Query Setup
   - Configured Athena query output location in S3.
   - Created a database and table for querying CloudTrail logs stored in S3.
   - Used Athena to run sample SQL queries to extract recent login events and API activity.
   - Collected screenshots of table creation and query results.

6. Cleanup
   - Deleted CloudTrail trails and emptied S3 buckets storing CloudTrail logs.
   - Disabled GuardDuty and removed associated data.
   - Deleted AWS Config rules, stopped and removed configuration recorder and delivery channels.
   - Removed CloudWatch log groups, metric filters and alarms created during the lab.
   - Deleted Athena tables and emptied/deleted the S3 bucket used for Athena query results.
   - Cleaned up IAM roles, policies and any other temporary resources created for lab purposes.
   
---

## Screenshots

*All relevant screenshots demonstrating each step are included in the screenshots/ folder of this repository.

| Order | File Name                                 | What it Shows                                      |
|-------|-------------------------------------------|----------------------------------------------------|
| 1     | awsconfig_rules_compliance_status.png     | AWS Config dashboard showing compliance status     |
| 2     | cloudtrail_trail_summary.png              | Multi-region CloudTrail trail summary              |
| 3     | cloudwatch_alarm_consolelogin_summary.png | CloudWatch alarm summary for ConsoleLogin events   |
| 4     | cloudwatch_metric_filter_consolelogin.png | CloudWatch metric filter for ConsoleLogin events   |
| 5     | guardduty_enabled_dashboard.png           | GuardDuty dashboard showing enabled status         |
| 6     | sample-cloudtrail-log-json.png            | Sample raw CloudTrail event JSON log for reference |

## Screenshot Explanations

1. awsconfig_rules_compliance_status.png: Displays the AWS Config dashboard with the compliance status of security rules, showing which rules are compliant or non-compliant.

2. cloudtrail_trail_summary.png: Multi-region CloudTrail trail summary page confirming that logging is enabled across all regions and logs are being sent to the configured S3 bucket.

3. cloudwatch_alarm_consolelogin_summary.png: Summary of the CloudWatch alarm configured to monitor ConsoleLogin events, indicating the alarm status and configuration.

4. cloudwatch_metric_filter_consolelogin.png: CloudWatch metric filter setup targeting ConsoleLogin events from CloudTrail logs for real-time monitoring.

5. guardduty_enabled_dashboard.png: GuardDuty dashboard confirming that threat detection is enabled and actively monitoring the AWS environment.

6. sample-cloudtrail-log-json.png: Sample snippet of raw CloudTrail event JSON, showing typical logged API activity details such as event name, time, user identity, and source IP address.

---

## JSONs Table

*JSON files are included in the /sample_jsons/ folder for reference in this repository.

| Order | File Name                               | What it Shows                                |
|-------|-----------------------------------------|----------------------------------------------|
| 1     | awsconfig_rule_noncompliant_sample.json | AWS Config non-compliance finding JSON       |
| 2     | cloudtrail_event_sample.json            | Sample CloudTrail event JSON                 |
| 3     | guardduty_sample_finding.json           | Sample GuardDuty finding JSON                |

---

## Lessons Learned

- Centralized logging with CloudTrail is essential for tracking all AWS API activity and forensic analysis.
- GuardDuty enhances security posture with automated threat detection powered by machine learning.
- AWS Config enables continuous compliance monitoring with customizable rules that detect misconfigurations.
- CloudWatch metric filters and alarms provide real-time alerting on suspicious activity.
- Athena enables flexible, fast querying of raw logs stored in S3, empowering security investigations and audits.

---

## References

- AWS CloudTrail Documentation
  https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html

- AWS GuardDuty Documentation
  https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html

- AWS Config Documentation
  https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html

- AWS CloudWatch Documentation
  https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/WhatIsCloudWatch.html

- AWS Athena Documentation
  https://docs.aws.amazon.com/athena/latest/ug/what-is.html

---

Sebastian Silva C. – July 2025 – Berlin, Germany
