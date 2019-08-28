# NetAppCdotBestPracticeReportForNAS
This is a PowerShell script to report upon detection and in a summery various best practices breaches on NetApp Cdot clusters used for NAS.

list of current best practices checks:
CNAMEs pointing to SVMs with high TTL

CNAMEs missing valid SPNs

Sessions using old CIFS protocols

CIFS Shares that don’t have exact match configuration in between DR and PROD

Qtrees without quota

Quota Errors Reported on Volumes

Soft limit quota breaches found

Volumes with quota is set on the qtree but disabled on the Volume

Quota SoftLimit And Threshold Need Alignment

Quota limit seems to be too high

Quota has not yet calculated for some Qtrees

Fpolicy is set on SVM but not connected

Fpolicy policy is set on SVM but not enabled

Snapshot reserve is not set on all the copies equally

The Volume snapshot reserve is set to too higher than the current snapshot usage

SVM root volume don’t have copies on all nodes

SnapMirrored Volumes that don’t have healthy copies on DR BK and RB SVMs
