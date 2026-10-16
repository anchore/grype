## Pre-Requisites

- A Kubernetes Cluster (cloud managed or on-prem [eg. minikube,Kind,etc] )
- kubectl cli install
- Basic understanding of kubernetes

### Installation

Although the namespace is already inside `grype-operator/manifests`.

```bash
kubectl create ns grype-operator-system
```

Now we have to install crd,rbac,cm,etc in short all manifests from `grype-operator/manifests`.

```bash
cd grype-operator
kubectl apply -f manifests/
```

You should see operator pod running in ns : `grype-operator-system`, like below :

```bash
kubectl get pods -n grype-operator-system

NAME                              READY   STATUS    RESTARTS   AGE
grype-operator-5645fcf69d-2mxf8   1/1     Running   0          46m
```

## Now Comes the interesting part, Testing the operator running 😘😎

```bash
kubectl run test-nginx --image=nginx:alpine
```

- Now as per our application or operator, grype operator will get triggered and create a job to scan the image used for above pod.
- When the job work is done , it will generate the vulnerability report for the scanned container/image and that can be checked with our custom resource and job pod is terminated.

```bash
kubectl get vr or kubectl get vulnerabilityreport

Output :

NAME                         POD          CRITICAL   HIGH   MEDIUM   LOW   AGE
test-nginx-74ccbdf4-report   test-nginx   0          1      2        6     52m
```

### For In-Depth Vulnerability Report for the Image :

```bash
kubectl describe vr test-nginx-74ccbdf4-report
```

Output :

```bash
Name:         test-nginx-74ccbdf4-report
Namespace:    default
Labels:       grype-operator.security.io/container=test-nginx
              grype-operator.security.io/pod=test-nginx
Annotations:  <none>
API Version:  security.grype.io/v1alpha1
Kind:         VulnerabilityReport
Metadata:
  Creation Timestamp:  2025-11-10T11:37:52Z
  Generation:          1
  Resource Version:    377766
  UID:                 8d034f77-ae8d-4582-87be-6d92a7fe3978
Spec:
  Container Reports:
    Container:  test-nginx
    Image:      nginx:alpine
    Summary:
      Critical:    0
      High:        1
      Low:         6
      Medium:      2
      Negligible:  0
      Total:       9
      Unknown:     0
    Vulnerabilities:
      Description:  An out-of-memory flaw was found in libtiff. Passing a crafted tiff file to TIFFOpen() API may allow a remote attacker to cause a denial of service via a craft input with size smaller than 379 KB.
      Id:           CVE-2023-6277
      Package:      tiff
      Severity:     Medium
      Version:      4.7.1-r0
      Description:  A segment fault (SEGV) flaw was found in libtiff that could be triggered by passing a crafted tiff file to the TIFFReadRGBATileExt() API. This flaw allows a remote attacker to cause a heap-buffer over
      Id:           CVE-2023-52356
      Package:      tiff
      Severity:     High
      Version:      4.7.1-r0
      Description:  An issue was found in the tiffcp utility distributed by the libtiff package where a crafted TIFF file on processing may cause a heap-based buffer overflow leads to an application crash.
      Id:           CVE-2023-6228
      Package:      tiff
      Severity:     Medium
      Version:      4.7.1-r0
      Description:  In tar in BusyBox through 1.37.0, a TAR archive can have filenames hidden from a listing through the use of terminal escape sequences.
      Id:           CVE-2025-46394
      Package:      busybox
      Severity:     Low
      Version:      1.37.0-r19
      Description:  In tar in BusyBox through 1.37.0, a TAR archive can have filenames hidden from a listing through the use of terminal escape sequences.
      Id:           CVE-2025-46394
      Package:      busybox-binsh
      Severity:     Low
      Version:      1.37.0-r19
      Description:  In tar in BusyBox through 1.37.0, a TAR archive can have filenames hidden from a listing through the use of terminal escape sequences.
      Id:           CVE-2025-46394
      Package:      ssl_client
      Severity:     Low
      Version:      1.37.0-r19
      Description:  In netstat in BusyBox through 1.37.0, local users can launch of network application with an argv[0] containing an ANSI terminal escape sequence, leading to a denial of service (terminal locked up) whe
      Id:           CVE-2024-58251
      Package:      busybox
      Severity:     Low
      Version:      1.37.0-r19
      Description:  In netstat in BusyBox through 1.37.0, local users can launch of network application with an argv[0] containing an ANSI terminal escape sequence, leading to a denial of service (terminal locked up) whe
      Id:           CVE-2024-58251
      Package:      busybox-binsh
      Severity:     Low
      Version:      1.37.0-r19
      Description:  In netstat in BusyBox through 1.37.0, local users can launch of network application with an argv[0] containing an ANSI terminal escape sequence, leading to a denial of service (terminal locked up) whe
      Id:           CVE-2024-58251
      Package:      ssl_client
      Severity:     Low
      Version:      1.37.0-r19
  Pod:              test-nginx
  Scan Time:        2025-11-10T11:37:52.206036Z
  Scanner:
    Name:    Grype
    Vendor:  Anchore
  Summary:
    Critical:    0
    High:        1
    Low:         6
    Medium:      2
    Negligible:  0
    Total:       9
    Unknown:     0
Events:          <none>
```


## Full Demo Video for Grype Operator for Kubernetes Clusters


https://github.com/user-attachments/assets/2dd85c3b-b30c-42c5-b589-efecd4423ab1

