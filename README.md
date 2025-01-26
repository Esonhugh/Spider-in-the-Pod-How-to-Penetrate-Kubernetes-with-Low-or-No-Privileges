---
title: Spider in the Pod - How to Penetrate Kubernetes with Low or No Privileges
date: 2025-01-01 03:00:00
tags:
  - kubernetes
  - cloud
  - hacking
  - pentest
  - post-exploitation
subtitle: K8Spider Tool Demo
---

[中文版在这里哦 Chinese Version here](./Chinese%20-%20Spider%20in%20the%20Pod%20-%20How%20to%20Penetrate%20Kubernetes%20with%20Low%20or%20No%20Privileges.md)

## Intro

Some common subjects of modern k8s attack methodology include **Role Based Access Control (RBAC)**, and the use of various container escape methods. Although k8s is substantially affected by these attacks, a more common scenario involves attacking k8s as a container orchestration system to schedule or deploy web applications without requiring special permissions.

Instead of attacking RBAC, web hackers often exploit web services to obtain a default permission service account, a high k8s and linux kernel version, and a container shell configured with default CAP.

So when all the attack methods used on k8s fail, what else can we do?

## What other privileges do we have?

What else can we do besides enumerating the container environment?

Generally speaking, a Kubernetes container can access the following attack surface

>Although this capability can be restricted by Network Policy resources, by default, everything is allowed. Additionally, this feature requires support from the CNI itself, which is mostly supported. Moreover, writing this policy is really challenging. If you want to give it a try, you can use the one provided by Cilium at https://editor.networkpolicy.io/

1.	Open ports of other containers under the same node
2.	Open ports of containers under other nodes
3.	Ports open on other node host machines
4.	Ports open on the current node’s host machine
5.	Service ports virtualized through Kubernetes Service
6.	Other internal services and ports. Our primary targets are apiserver, etcd, Kubelet, and services that may exist from cloud service providers

Now how do we discover these ports or IPs?

Some hackers with knowledge of internal network testing might try using a bypassed fscan, or perhaps a statically compiled nmap. There are several issues with this approach:

1. Although these tools are all effective in their own respects, the k8s network segment is quite complex. There are three types of corresponding segments: service segment (default ⁠`10.96.0.0/12`), Pod segment (default `⁠10.244.0.0/12`, ⁠`172.16.0.1/12`), and host segment default (⁠`192.168.X+.0/24`) or in the case of cloud services, it will be like 10.x, etc., all of which are across different segments that do not intersect, meaning that you can’t see this information just by looking at the network card, for example checking `ifconfig` or `ip addr show` won’t reveal this information.
2. The istio-like injected sidecar intercepts all your requests through IPtables and then forwards them remotely via sidecar.This raises an issue where its transparent mode actively changes your TCP state to turn SYN scan traffic into fake positives; See [Detailed Explanation on Sidecar Injection in Istio, Transparent Traffic Hijacking and Traffic Routing Process](https://jimmysong.io/blog/sidecar-injection-iptables-and-traffic-routing/#sidecar-%E6%A8%A1%E5%BC%8F). Another issue is related to network permissions; for instance, techniques relying on protocols such as ICMP for probing may require NET_ADMIN permissions to use SOCKET_RAW for sending ICMP packets which might be restricted within containers.
## Common Information Leakage

### Java SpringCloud Kubernetes with Heapdump 

Let’s start with this piece of cake. As the first unauthorized access point with certain risks, Java heapdump is commonly found in Java applications. In SpringCloud Kubernetes, a service account (sa) is configured by default with permissions to access ConfigMap and Secrets Get List.
#### Case 1: Heapdump to Cluster Initial Access

At the beginning of 2023, I published an article on my blog about Heapdump leading to unauthorized takeover of a cluster. If you are interested in the specific attack process, you can visit [here](https://eson.ninja/review/springcloud-java-heapdump-security/) for detailed information.

In a nutshell, this article mainly discusses exploiting SpringCloud Kubernetes and actuator heapdump together to download heapdump without authorization, analyzing the k8s service account token stored in fabric8 kubernetes client and okhttp client. Then using this token to directly access apiserver and obtain the entire cluster configuration without permission. Of course, sensitive information such as AWS access tokens may also be included in the heapdump, making it even more dangerous.

### DNS

After k8spider's vigorous promotion (if you haven't seen it yet, you can check it out [here](https://github.com/esonhugh/k8spider)),  it has been mentioned many times as a common method of k8s internal network service discovery.

It currently covers the following types of enumeration

1. Basic k8s `any.any.any.svc.cluster.local` service dump
> 	This is also one of the scanning functions integrated in CDK
2. Querying the SRV record to get the corresponding port number by continuously querying the ptr of the service cidr IP address
  > 	This is the official method of service discovery in the Kubernetes DNS protocol, which works for almost any cluster unless the DNS request is handled specially or. Headless services also cannot be enumerated by this method because it doesn't allocate a cluster IP address under service ip cider. 
3. Querying the SRV record to get the corresponding port number by continuously querying the ptr of the pod cide IP address
  > 	This is am official method of service discovery in the Kubernetes DNS protocol as well, which works for most clusters unless the pod name is handled specially, this can also discover the corresponding port and valid LAN pod address and also works for headless service.
4. Internal AXFR zone record transfer
  > 	When multiple k8s clusters have shared zone records between coredns and other DNS servers, it may cause other pods to obtain axfr records.
5. With pod verified in the coredns configuration, traverse and enumerate the A records of the surrounding IP addresses to try to get valid IP addresses, include the pod IP address which is not exposed by service/headless service.
  > 	When coredns is configured as pod verified,  for example, it adds metadata autopath plugins, when dns `ip.<ns>.pod.cluster.local` corresponding pod ip address does not exist, it will force to return NXDOMAIN instead of directly returning the recorded address. By analyzing these, valid LAN internal addresses can be resolved.

After going through these stages of development, k8spider can now enumerate internal services for the k8s DNS protocol agreements/coredns, and can successfully enumerate k8s services and corresponding ports. It can be said that it can grasp the general services and information of the other party's cluster.

When methods 2 and 3 are combined, we can directly attain the corresponding service pod + service address, and the corresponding port number. This is very effective for internal service discovery.

By the way, I have also written the command `whereisdns` to help you discover the service even if the default DNS location of the current pod is modified (this is more common in cases where you need to directly access remote IDE/VSCode servers, etc.).

#### Case 2: Gain Cluster Admin via Weave Scope Internal Unauthenticated Service

[Weave Scope](https://github.com/weaveworks/scope) was a well-known k8s dashboard from a long time ago that is unauthenticated by default. The good news is that it is only accessible on the internal network. For the internal network, its DNS name is usually `weave-scope-app.weave.svc.cluster.local`. However, if you find this service or a similar name in the k8spider/dns scan results, congratulations. You have succeeded in most of the work. For you, the cluster admin is only one port forwarding away. Access this port, and you can directly take over the entire cluster.

### Metrics

#### kube-state-metrics

Monitoring metrics are also very common services in the cloud. For operation and visualization, metrics services usually do not require authorization and are open to the outside world(in kubernetes scope). Although there is not much sensitive information in here, this usually requires specific judgment based on the specific situation.

And in one of them, we are most concerned about cluster metrics. Among them, the most representative one is [kube-state-metrics](https://github.com/kubernetes/kube-state-metrics), which is the official metrics service of k8s. It collects information about workloads, configurations, networks, and even role bindings in the cluster and exposes the `/metrics` interface on port 8080.

So, in these two days, I have integrated another feature in k8spider to analyze the metrics indicators. It can reverse parse each metrics information in the text content and restore it to k8s resource information that can be understood and read. It can do:

1. Match metrics related to ConfigMaps, namespace, and ConfigMap name
2. Match metrics related to Secrets, namespace, and Secret name
3. Match 2 kinds of metrics related to nodes, kernel version, OS image, container runtime version, provider ID, and internal IP **node permissions** (whether it is a master)
4. Match metrics related to Pods, namespace, Pod name, node, host IP, and Pod IP
5. Match metrics related to containers, namespace, Pod, container, image specification, and image
6. Match metrics related to the init-container in the Pod, similar to the container tags
7. Match metrics related to CronJobs, namespace, CronJob name, scheduling time, and concurrency strategy
8. Match metrics related to service accounts, namespace, mounted Pod, and service account 
9. Match metrics related to services, namespace, service, cluster IP, external name, and load balancer IP
10. Match 2 kind of metrics related to endpoint slice, about namespace, endpoint name, IP list, and port list
11. **Match metrics related to persistent volumes, adding storage class, disk name from different providers, NFS server and path, CSI driver and volume handle, local path and file system, host path and type, etc.**
12. Match metrics related to Webhook, such as **mutating webhook** or validating webhook, to know the corresponding service location information.

Among of them, the two most interesting ones are persistent storage and webhook information.
##### Case 3 Leakage of sensitive information via mutating webhook

When the cluster is configured with a mutating webhook to inject sensitive configurations such as AccessKey and there is no mandatory verification that the request comes from the APIserver, we can bypass the apiserver 's authentication by forging an Admission Review resource to deceive the other party into injecting sensitive configuration files into the Review result.

Of course, this feature depends on the configuration of the victim group and the specific business needs. Generally speaking, this feature is less likely to occur in the cluster.

For example, the AWS pod-identity-webhook will inject the corresponding AWS Token file into the pod. The process is roughly as follows:

![](https://d2908q01vomqb2.cloudfront.net/fe2ef495a1152561572949784c16bf23abb28057/2023/12/20/Pod-Identity-Worklow.jpg)

Similarly, we can obtain sensitive configuration information by attacking this type of mutation webhook.

> But aws pod-idetity-webhook is secure and not vulnerable to this attack. It will only inject the token file mounts into the pod spec instead of directly providing the token value in the environment variable, and it will also verify the request source whether the request comes from the apiserver.

However, when the validating webhook indicates that the cluster may have some security services running, if it detects illegal configurations, it will intercept various resource creation, deletion, modification, and other operations. If the webhook does not force verification that the request comes from the APIserver, we can directly access the webhook service to forge a configuration creation and get the corresponding validating result. for example, kyverno, opa, and  [veinmind](https://github.com/chaitin/libveinmind) etc.

##### Case 4: Attacking persistent Database backend with NFS/CSI storage 

Kubernetes PV is often used to store persistent database data directories so that the database backend can be operated as a stateless service. Therefore, you may find that some databases (possibly) will use nfs / aws ebs / aliyun nas for processing. 

However, the NFS system protocol is relatively old, and the permission control of NFS is not particularly strong. So when we find a remote database storage with NFS, we can use tools such as nfs-cat (or write an nfs client by ourselves, which has been added to the k8spider's schedule), or port forwarding (usually 2049 and 111 rpcbinding) to directly access the corresponding nfs mount, or even try to mount it locally when the network speed is good. Then refer to the corresponding database recovery document to directly obtain passwords and other information from the database data files. Including the authentication password of the SQL itself.

And all of these operations actually do not require any permissions for the cluster, just a pod shell is enough.

> k8spider have a plan to add NFS client feature for u in the future, so stay tuned.

##### Extended Abusing: RBAC with Metrics power

For hackers, creating pod resources means they can access mounts in the pod and try to read sensitive configuration files such as configmap or secret. But pod permissions and secrets configmap permissions may not necessarily exist at the same time.

So if we can still leak the names of configmaps and secrets, then with pod create RBAC, and we actually have the ability to obtain the content of these things. And kube-state-metrics just provides such a channel, allowing us to obtain all the configuration information used in the entire cluster, even without permissions.

#### Coredns metrics

Coredns metrics do not have anything special, but it will open a metrics on port 9135 by default in its pod. The information it leaks is mainly the installation and use of plugins. So you can combine the above DNS exploitation techniques to see if advanced DNS features are enabled, such as metadata and transfer.

If you found any interesting plugins, you are welcome to come back to the DNS section to see if you can make additional findings.

## Ending Words

In conclusion, kubernetes is a very complex system, depending on its own design and configuration, as well as the specific usage of the business side. For hackers, its complexity also means that its attack surface is more extensive.

So, in this article, I tried to look at the risk surface that k8s may have from the perspective of a hacker. These attack methods are not high-level techniques, but common information leakage and exploitation methods. Of course, this is just the beginning.

> I'm glad to bring you two cloud-based attack games in SUCTF 2025, one of which is based on metrics information leakage + nfs. Hope you like it. And my writeup is available [here](https://github.com/team-su/SUCTF-2025/tree/main/web/SU_easyk8s/writeup)

## Thanks 

1. [Bryan](https://github.com/bryanmcnulty) gave me a lot of help and guidance during the translation process.

## Sponsor

https://www.patreon.com/c/Skyworshiper 