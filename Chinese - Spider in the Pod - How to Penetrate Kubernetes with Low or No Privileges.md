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
## Intro

现代 k8s 攻防主要必修课第一节一般是 RBAC 相关内容，亦或是使用各种容器逃逸方式进行逃逸。虽然 k8s 受此几种攻击影响较大，但是更为常见的情况是对方仅仅将 k8s 作为容器编排系统，对各类不需要特殊权限的 web 应用程序进行调度或者简单部署。

由于这类系统对熟悉 web 利用的黑客而言更容易攻破，而往往攻击者很容易得到一个 default 权限 sa 、高 linux 内核版本的高版本 k8s 以及配置了默认 CAP 的容器 shell ，而非更易受影响的配置了 rbac 的 serviceaccount 所在的 k8s operator 或者 controller 。

那么当一切的一切 k8s 利用的攻击手法都失效的时候，我们还可以做什么？
## 我们还有什么权限？

问题回到一开始，除了常规枚举容器环境以外我们还有什么能力。

通常而言对于一个 k8s 容器而言，他可以轻易访问

>虽然这个能力可以被 Network Policy 资源进行限制，但是默认情况下都是全部通畅。而且这个功能需要 CNI 本身对此有支持，当然大部分都是支持的。此外这个 策略真的很难写如果你想要尝试一下可以使用 Cilium 家出品的 https://editor.networkpolicy.io/ 

1. 相同节点下的其它容器开放的端口
2. 其他节点下的其它容器开放的端口
3. 其它节点宿主机开放的端口
4. 当前节点宿主机开放的端口
5. 通过 Kubernetes Service 虚拟出来的服务端口
6. 内网其它服务及端口，主要目标可以设定为 apiserver、etcd、Kubelet 以及云服务厂商可能存在的服务 等

那么接下来的问题是如何发现这些端口或 ip 呢？ 

打习惯了内网的师傅，一般是从口袋里掏了一个免杀的 fscan 出来或者掏了个静态编译 nmap 这种大玩具。Nono。这里有几个问题：

1. 虽然这些工具都很有效，但是 k8s 网段较为复杂，其中对应的网段有三类，服务网段（默认`10.96.0.0/12`） Pod 所在网段（默认 `10.244.0.0/12` `172.16.0.1/12` ），宿主机网段 默认（`192.168.X.0/24`） 或者云服务情况下就会在 10.x 等等，这些都是跨网段的，并且不交叉，这意味着仅仅只看网卡，例如看 ifconfig 或者 ip addr show 是看不到这些信息的。
2. istio 类注入的 sidecar 会通过 ip 桌子 (iptables) 拦截 你的所有请求，然后通过 sidecar 转发给远程。这里会有一个问题，他的透传模式会主动使得你的 TCP 状态使得你的 SYN 扫描流量变为 fake positive (假阳性)，[Istio 中的 Sidecar 注入、透明流量劫持及流量路由过程详解 ](https://jimmysong.io/blog/sidecar-injection-iptables-and-traffic-routing/#sidecar-%E6%A8%A1%E5%BC%8F) 此外还有一个问题是网络权限的问题，例如依赖 ICMP 等协议进行探测的手法中，ICMP 发包可能需要 SOCKET_RAW 这类 NET_ADMIN 权限，而容器内可能这些都是被限制的。
## 通用信息泄漏

### Java SpringCloud Kubernetes with Heapdump 

先来一篇开胃小菜，作为第一个具有一定危害的利用无权限利用点，Java heapdump 普遍存在于 java 应用程序中，而在 SpringCloud Kubernetes 中会默认配置出一个具有 ConfigMap 与 Secrets Get List 权限的服务账户（sa）。

#### 案例一 Heapdump 攻入集群

在 23 年年初，我在自己的 blog 中发表过一篇 [Heapdump 导致最后未授权接管集群的文章](https://eson.ninja/review/springcloud-java-heapdump-security/) 如果你有兴趣查看具体的攻击过程，不妨移步 blog.eson.ninja 一读。

> 这里简单概述一下文章的内容，主要是在未授权情况下，通过获取 SpringCloud Kubernetes 和 actuator heapdump 联合利用，下载 heapdump 后分析出 fabric8 kubernetes client 和 okhttp client 中  存放的 k8s service account token，然后通过这个 token 直接访问 apiserver，最后通过 apiserver 直接获取到了集群的所有配置信息。
> 
> 当然，heapdump 可能还存放有 AWS Accesskey 之类的信息，那么这个就更加危险了。
### DNS

DNS 利用这一点经过 k8spider 的使劲儿宣传（如果你还没有看过你可以看看 [这里](https://github.com/esonhugh/k8spider) ) ，以及多次提及已经是很常用的 k8s 内网服务发现的手法了。

他目前涵盖了如下几类枚举

1. 最基础的 k8s any.any.any.svc.cluster.local 地址的服务 dump
	> 这个也是 CDK 集成的扫描功能之一
2. 通过连续 service cidr ip 地址查询 ptr 从而枚举到对应的存在的服务，并且查询 SRV 记录得到对应的端口号 
	> Kubernetes DNS 协议中规定的服务发现手法 对付几乎任何集群都有效 除非 DNS 请求有特殊处理，此外对于 headless 类服务，由于不会增加 service ip 所以不会占用 service cidr ip 地址。
3. 通过连续 pod cide ip 地址查询 ptr 从而枚举得到对应的存在的暴露服务，并且查询 SRV 记录可以得到对应的端口号
	> Kubernetes DNS 协议规定的服务发现手法 对大部分集群有效 除非 pod name 有特殊处理，这个可以也可以发现对应的端口 和有效的 局域网 pod 地址
4. 内网 AXFR 区域记录传输
	> 当拥有多个 k8s 集群存在 coredns 和其他 dns 服务器之间传输共享区域记录时，会导致可能其他的 pod 也可以获取得到 axfr 记录
5. 在 coredns 配置为 pod verified 情况下，遍历枚举周围 ip 地址的 A 记录尝试获取有效的 IP 地址， 这也包括了没有被 service / headless service 暴露的 pod ip 地址。
	> 当 Coredns 配置为 Pod Verified 的时候，例如启用了 metadata autopath 等插件，当 dns `ip.<ns>.pod.cluster.local` 对应的 pod ip 地址不存在，则会强制返回 NXDOMAIN 而不是直接返回记录的地址。通过分析这些可以解析出有效的局域网内部地址。

经过这些阶段的发展，目前 k8spider 可以针对 k8s dns 协议约定 / coredns 进行内网服务枚举，并且可以成功枚举出来 k8s service 与对应的端口。可以说，基本对方集群的大概服务和信息尽收眼底。

甚至当 2 3 联合的时候，我们可以通过这类手法直接获取到对应的 service pod + service address 地址，以及对应的端口号。这个对于内网服务发现是非常有效的。

此外，我额外编写了 whereisdns 命令，帮助大家在 k8s 环境中，即使当前 pod 修改了默认的 dns 位置（这类比较常见的情况一般是需要直接对外访问的远程 IDE / VSCode 服务器等），但是仍然可以尝试发现它 。
#### 案例二 weave scope 内网服务未授权直达 cluster admin

 [Weave Scope](https://github.com/weaveworks/scope) 是一个很早以前很有名的 k8s dashboard 但是问题是他默认情况是未授权的 dashboard。但是好就好在他开在内网，外网默认是访问不到的。对内网而言，他的 DNS 名称通常为 weave-scope-app.weave.svc.cluster.local. 不过如果你在 k8spider / dns 扫描结果中发现了该服务或者类似的名称，那么恭喜你。你已经成功一大半了，对你而言 cluster admin 只差一个端口转发。访问其端口，便可以直接超控整个集群。
### Metrics

#### kube-state-metrics

监控指标也是云上很常见的服务，对运维和可视化而言，metrics 类服务通常不需要授权而且对集群范围内开放，敏感信息虽然不是很多但是这通常需要具体情况具体判断。

而其中，我们最为关心的应该是集群类指标。而在这其中最为有代表性的是 [kube-state-metrics](https://github.com/kubernetes/kube-state-metrics) ，这是 k8s 官方的 metrics 服务。他会采集集群中工作负载，配置，网络，甚至是角色绑定等信息，并且将其打开 8080 端口暴露 `/metrics` 接口中。

这两天我在 k8spider 中集成了另一个功能来分析 metrics 指标。他可以反向解析 metrics 文本内容中的每一条 metrics 信息，并且重新将其恢复为可以理解阅读的 k8s 资源信息，他可以做到：

1. 匹配与 ConfigMaps 相关的指标，命名空间和 ConfigMap 名称
2. 匹配与 Secrets 相关的指标，命名空间和 Secret 名称
3. 匹配与节点相关的指标，内核版本、操作系统镜像、容器运行时版本、提供商ID和内部IP **节点权限**（是否为 mater）
4. 匹配与 Pods 相关的指标，命名空间、Pod 名称、节点、主机 IP 和 Pod IP 
5. 匹配与容器相关的指标，命名空间、Pod、容器、镜像规格和镜像
6. 匹配与 Pod 中的初始化容器相关的指标，与容器相似的标签
7. 匹配与 CronJobs 相关的指标，命名空间、CronJob 名称、调度时间和并发策略
8. 匹配与服务账户相关的指标，命名空间、挂载的 Pod 和服务账户
9. 匹配与服务相关的指标，命名空间、服务、集群 IP、外部名称和负载均衡器 IP 
10. 匹配与端点地址相关的指标，命名空间、端点和 IP 列表和端口号列表
11. **匹配与持久卷相关的指标，添加存储类、不同提供商的磁盘名称、NFS服务器和路径、CSI驱动程序和卷句柄、本地路径和文件系统、主机路径和类型等各种属性**
12. 匹配与 Webhook 相关的指标，例如 **mutating webhhook** 或者 validating webhook，得知对应的服务位置信息。

其中最有意思的是持久化存储和 webhook 两类信息。
##### 案例三： 泄漏注入的敏感配置信息

当集群配置了 mutating webhook 来注入类似 AccessKey 等敏感配置、并且没有强制验证请求来源来自 APIserver 的时候 ，我们可以直接绕过 apiserver 的鉴权，伪造一个 Admission Review 资源来欺骗对方将敏感配置文件注入到 Review 结果中。

当然这个特性非常吃受害者集群的配置和具体业务的需求情况，一般来说遇到这种集群机会较少。

例如 AWS pod-identity-webhook 会将对应的 AWS STSToken file 注入到 pod 中，其流程大概为 

![](https://s3.cn-north-1.amazonaws.com.cn/awschinablog/eks-certification-and-authorization-practice19.jpg)

类似的，我们可以通过攻击此类 mutation webhook 用以获得对应的敏感配置信息。

> 当然，aws pod-identity-webhook 本身是有一定的安全性的，例如他不会直接在环境变量中注入 token 的具体值，而是提供文件挂载，使得最后 patch 完后的 pod spec 我们任然不能获取到具体的 acesskey secretskey 和 sts token，同时他也会对请求来源进行验证。

而 validating webhook 可以说明当前的集群可能存在某些安全服务在运行，如果一旦检查到对应的非法配置，则会对各种资源的创建、删除、修改等操作进行拦截，如果 webhook 也没有强制验证请求来源来自 APIserver 的时候，我们可以通过直接访问 webhook 服务来针对性的伪造配置的创建并且获取对应 validating 的结果。例如 kyverno 和 [veinmind](https://github.com/chaitin/libveinmind) 等。
##### 案例四： 攻击数据库持久化存储

K8S 中的 PV 常常会用于存放持久化的数据库 data dir 从而使得数据库后端可以变为无状态服务来运维。所以常常可以看到部分集群中的数据库（可能）会使用 nfs / aws ebs / aliyun nas 进行处理。

但是 NFS 的系统协议相对而言比较老旧， 而且 NFS 的权限管控其实也不是特别强。所以当我们发现了存在 nfs 的数据库远程存储的时候，可以使用 nfs-cat 等等工具 （或者自己写一个 nfs client ，k8spider 的排期中已经加上了这个功能），或者端口转发 （通常是 2049 和 111 rpcbinding）来直接访问对应的 nfs 挂载，甚至在网络速度还可以的时候，尝试直接挂载在本地。然后参考对应数据库的数据恢复文档直接从数据库 data 文件中获取到密码等等信息。包括 sql 自身的鉴权密码。

而这些操作实际上都不需要任何对于集群的权限，只需要一个 pod shell 就可以了。

> k8spider 有计划在将来为您添加NFS客户端功能，敬请期待。
##### 扩展衍生：RBAC + Metrics 联合利用

对于黑客而言，可以创建 pod 资源同时也意味着可以在 pod 中访问挂载，并且尝试读取敏感配置文件 configmap 或 secret。但是 pod 权限与 secrets configmap 权限不一定会同时存在。

如果我们还可以泄漏 configmap 和 secrets 的名称，那么配合 pod create rbac 我们就实际的拥有了获取这些东西对应的内容的能力。而这里 kube-state-metrics 正好提供了这样一个渠道，使得我们即使在无权限情况下，也可以获取整个集群中所用的配置信息。
#### Coredns metrics

coredns 的 metrics 没有特殊的东西，但是 他会默认在自己的 pod 的 9135 端口开放一个 metrics ，他会泄漏的信息主要是安装和使用的插件，所以可以结合上面对于 DNS 的利用技巧看一下，是否有高级的 DNS 特性被启用了，例如 metadata 和 transfer 。

如果你发现他启用了这两个特性，欢迎回到上一章节。

## End 结语

总而言之，言而总之，kubernetes 是一个非常复杂的系统，其取决于其本身的设计和配置，取决于业务方的具体使用情况，而对于黑客而言，他的复杂性也意味着他的攻击面更加广泛。

在这篇文章中，我尝试从一个黑客的角度来看待 k8s 底层中，通常可能具有的风险面。这些攻击手法并不是什么高深的技术，而是一些常见的信息泄漏和利用方式。当然，这只是开始。

> 很高兴在 SUCTF 2025 中，给大家带来两道云方向的攻防题目，其中一道题目就是基于 metrics 信息泄漏 + nfs 的。希望大家能够喜欢。我的题解可以在[这里](https://github.com/team-su/SUCTF-2025/tree/main/web/SU_easyk8s/writeup) 获得。

## 特别感谢

1. [Bryan](https://github.com/bryanmcnulty) 在英文版文章的翻译过程中提供了很多帮助和指导，同时，他也是很酷的 HackThebBox 黑客玩家，和我一起学习过 AD 和云。

2. CSA GCR 云渗透测试工作组的成员们，他们在这个领域的研究和实践经验对我有很大的帮助，我与多位成员在 kubernetes 安全方向上的讨论，激发了我编写这篇文章的灵感。

## Sponsor

https://www.patreon.com/c/Skyworshiper 
