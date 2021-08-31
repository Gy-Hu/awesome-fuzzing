# Awesome Fuzzing [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

> [Fuzzing](https://en.wikipedia.org/wiki/Fuzzing) or fuzz testing is an automated software testing technique that involves providing invalid, unexpected, or random data as inputs to a computer program. The program is then monitored for exceptions such as crashes, failing built-in code assertions, or potential memory leaks. Typically, fuzzers are used to test programs that take structured inputs. 

A curated list of references to awesome Fuzzing for security testing. Additionally there is a collection of freely available academic papers, tools and so on.

Your favorite tool or your own paper is not listed? Fork and create a Pull Request to add it!


## Contents

- [Books](#books)
- [Papers](#papers)
- [Tools](#tools)
- [Platform](#platform)


## Books
- [The Fuzzing Book](https://www.fuzzingbook.org/) (2019)
- [The Art, Science, and Engineering of Fuzzing: A Survey](https://ieeexplore.ieee.org/document/8863940) (2019) - 
Actually, this document is a paper, but it contains more important and essential content than any other book.
- [Fuzzing for Software Security Testing and Quality Assurance, 2nd Edition](https://www.amazon.com/Fuzzing-Software-Security-Testing-Assurance/dp/1608078507/) (2018)
- [Fuzzing: Brute Force Vulnerability Discovery, 1st Edition](https://www.amazon.com/Fuzzing-Brute-Force-Vulnerability-Discovery/dp/0321446119/) (2007)
- [Open Source Fuzzing Tools, 1st Edition](https://www.amazon.com/Open-Source-Fuzzing-Tools-Rathaus/dp/1597491950/) (2007)


## Talks
- [Effective File Format Fuzzing](https://youtu.be/qTTwqFRD1H8), Black Hat Europe 2016
- [Adventures in Fuzzing](https://www.youtube.com/watch?v=SngK4W4tVc0), NYU Talk 2018
- [Fuzzing with AFL](https://www.youtube.com/watch?v=DFQT1YxvpDo), NDC Conferences 2018

## Papers
To achieve a well-defined scope, I have chosen to include publications on fuzzing in the last proceedings of 4
top major security conferences and others from Jan 2008 to Jul 2019.
It includes (i) Network and Distributed System Security Symposium (NDSS), (ii) IEEE Symposium on
Security and Privacy (S&P), (iii) USENIX Security Symposium (USEC), and (iv) ACM Conference on Computer and Communications Security (CCS).


### The Network and Distributed System Security Symposium (NDSS)
- [PGFUZZ: Policy-Guided Fuzzing for Robotic Vehicles, 2021](https://www.ndss-symposium.org/wp-content/uploads/ndss2021_6A-1_24096_paper.pdf)
- [Reinforcement Learning-based Hierarchical Seed Scheduling for Greybox Fuzzing, 2021](https://www.ndss-symposium.org/wp-content/uploads/ndss2021_6A-4_24486_paper.pdf)
- [WINNIE : Fuzzing Windows Applications with Harness Synthesis and Fast Cloning, 2021](https://www.ndss-symposium.org/wp-content/uploads/ndss2021_6A-3_24334_paper.pdf)
- [Favocado:Fuzzing the Binding Code of JavaScript Engines Using Semantically Correct TestCases, 2021](https://sefcom.asu.edu/publications/favocado-ndss21.pdf)
- [HFL: Hybrid Fuzzing on the Linux Kernel, 2020](https://www.unexploitable.systems/publication/kimhfl/)
- [HotFuzz: Discovering Algorithmic Denial-of-Service Vulnerabilities Through Guided Micro-Fuzzing, 2020](https://www.researchgate.net/publication/339164746_HotFuzz_Discovering_Algorithmic_Denial-of-Service_Vulnerabilities_Through_Guided_Micro-Fuzzing)
- [HYPER-CUBE: High-Dimensional Hypervisor Fuzzing, 2020](https://www.syssec.ruhr-uni-bochum.de/media/emma/veroeffentlichungen/2020/02/07/Hyper-Cube-NDSS20.pdf)
- [Not All Coverage Measurements Are Equal: Fuzzing by Coverage Accounting for Input Prioritization, 2020](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24422.pdf)
- [CodeAlchemist: Semantics-Aware Code Generation to Find Vulnerabilities in JavaScript Engines, 2019](https://daramg.gift/paper/han-ndss2019.pdf)
- [PeriScope: An Effective Probing and Fuzzing Framework for the Hardware-OS Boundary, 2019](https://people.cs.kuleuven.be/~stijn.volckaert/papers/2019_NDSS_PeriScope.pdf)
- [REDQUEEN: Fuzzing with Input-to-State Correspondence, 2019](https://www.syssec.ruhr-uni-bochum.de/media/emma/veroeffentlichungen/2018/12/17/NDSS19-Redqueen.pdf)
- [Send Hardest Problems My Way: Probabilistic Path Prioritization for Hybrid Fuzzing, 2019](https://www.cs.ucr.edu/~heng/pubs/digfuzz_ndss19.pdf)
- [Life after Speech Recognition: Fuzzing Semantic Misinterpretation for Voice Assistant Applications, 2019](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_08-4_Zhang_paper.pdf)
- [INSTRIM: Lightweight Instrumentation for Coverage-guided Fuzzing, 2018](https://www.ndss-symposium.org/wp-content/uploads/2018/07/bar2018_14_Hsu_paper.pdf)
- [IoTFuzzer: Discovering Memory Corruptions in IoT Through App-based Fuzzing, 2018](http://wp.internetsociety.org/ndss/wp-content/uploads/sites/25/2018/02/ndss2018_01A-1_Chen_paper.pdf)
- [What You Corrupt Is Not What You Crash: Challenges in Fuzzing Embedded Devices, 2018](http://s3.eurecom.fr/docs/ndss18_muench.pdf)
- [Enhancing Memory Error Detection for Large-Scale Applications and Fuzz Testing, 2018](https://lifeasageek.github.io/papers/han:meds.pdf)
- [Vuzzer: Application-aware evolutionary fuzzing, 2017](https://www.ndss-symposium.org/ndss2017/ndss-2017-programme/vuzzer-application-aware-evolutionary-fuzzing/)
- [DELTA: A Security Assessment Framework for Software-Defined Networks, 2017](https://www.ndss-symposium.org/wp-content/uploads/2017/09/ndss201702A-1LeePaper.pdf)
- [Driller: Augmenting Fuzzing Through Selective Symbolic Execution, 2016](https://cancer.shtech.org/wiki/uploads/2016---NDSS---driller-augmenting-fuzzing-through-selective-symbolic-execution.pdf)
- [Automated Whitebox Fuzz Testing, 2008](https://www.ndss-symposium.org/wp-content/uploads/2017/09/Automated-Whitebox-Fuzz-Testing-paper-Patrice-Godefroid.pdf)


### IEEE Symposium on Security and Privacy (IEEE S&P)
- [StochFuzz: A New Solution for Binary-only Fuzzing, 2021](https://github.com/ZhangZhuoSJTU/StochFuzz)
- [NtFuzz: Enabling Type-Aware Kernel Fuzzing on Windows with Static Binary Analysis, 2021](https://ieeexplore.ieee.org/document/9519448)
- [One Engine to Fuzz ’em All: Generic Language Processor Testing with Semantic Validation, 2021](https://changochen.github.io/publication/polyglot_sp_2021_to_appear.pdf)
- [DIANE: Identifying Fuzzing Triggers in Apps to Generate Under-constrained Inputs for IoT Devices, 2021](https://conand.me/publications/redini-diane-2021.pdf)
- [DIFUZZRTL: Differential Fuzz Testing to Find CPU Bugs, 2021](https://lifeasageek.github.io/papers/jaewon-difuzzrtl.pdf)
- [SAVIOR: Towards Bug-Driven Hybrid Testing, 2020](https://arxiv.org/pdf/1906.07327.pdf)
- [RetroWrite: Statically Instrumenting COTS Binaries for Fuzzing and Sanitization, 2020](https://www.cs.purdue.edu/homes/dxu/pubs/SP20.pdf)
- [Fuzzing JavaScript Engines with Aspect-preserving Mutation, 2020](https://jakkdu.github.io/pubs/2020/park:die.pdf)
- [IJON: Exploring Deep State Spaces via Fuzzing, 2020](https://www.syssec.ruhr-uni-bochum.de/media/emma/veroeffentlichungen/2020/02/27/IJON-Oakland20.pdf)
- [Krace: Data Race Fuzzing for Kernel File Systems, 2020](https://www.cc.gatech.edu/~mxu80/pubs/xu:krace.pdf)
- [Pangolin:Incremental Hybrid Fuzzing with Polyhedral Path Abstraction, 2020](https://qingkaishi.github.io/public_pdfs/SP2020.pdf)
- [RetroWrite: Statically Instrumenting COTS Binaries for Fuzzing and Sanitization, 2020](https://www.semanticscholar.org/paper/RetroWrite%3A-Statically-Instrumenting-COTS-Binaries-Dinesh-Burow/845cafb153b0e4b9943c6d9b6a7e42c14845a0d6)
- [Full-speed Fuzzing: Reducing Fuzzing Overhead through Coverage-guided Tracing, 2019](https://www.computer.org/csdl/proceedings-article/sp/2019/666000b122/19skgbGVFEQ)
- [Fuzzing File Systems via Two-Dimensional Input Space Exploration, 2019](https://www.computer.org/csdl/proceedings-article/sp/2019/666000a594/19skfLYOpaw)
- [NEUZZ: Efficient Fuzzing with Neural Program Smoothing, 2019](https://www.computer.org/csdl/proceedings-article/sp/2019/666000a900/19skg5XghG0)
- [Razzer: Finding Kernel Race Bugs through Fuzzing, 2019](https://www.computer.org/csdl/proceedings-article/sp/2019/666000a296/19skfwZLirm)
- [Angora: Efficient Fuzzing by Principled Search, 2018](http://web.cs.ucdavis.edu/~hchen/paper/chen2018angora.pdf)
- [CollAFL: Path Sensitive Fuzzing, 2018](http://chao.100871.net/papers/oakland18.pdf)
- [T-Fuzz: fuzzing by program transformation, 2018](https://nebelwelt.net/publications/files/18Oakland.pdf)
- [Skyfire: Data-Driven Seed Generation for Fuzzing, 2017](https://www.ieee-security.org/TC/SP2017/papers/42.pdf)
- [Program-Adaptive Mutational Fuzzing, 2015](https://softsec.kaist.ac.kr/~sangkilc/papers/cha-oakland15.pdf)
- [TaintScope: A checksum-aware directed fuzzing tool for automatic software vulnerability detection, 2010](https://ieeexplore.ieee.org/abstract/document/5504701)

### USENIX Security
- [ICSFuzz: Manipulating I/Os and Repurposing Binary Code to Enable Instrumented Fuzzing in ICSControlApplications, 2021](https://www.usenix.org/system/files/sec21fall-tychalas.pdf)
- [The Use of Likely Invariants as Feedback for Fuzzers, 2021](https://www.usenix.org/system/files/sec21-fioraldi.pdf)
- [aPiCraft: Fuzz Driver Generation for Closed-source SDK Libraries, 2021](https://www.usenix.org/system/files/sec21-zhang-cen.pdf)
- [Token-LevelFuzzing, 2021](https://www.usenix.org/system/files/sec21-salls.pdf)
- [unifuzz: A Holistic and Pragmatic Metrics-Driven Platform for Evaluating Fuzzers, 2021](https://www.usenix.org/system/files/sec21summer_li-yuwei.pdf)
- [Android SmartTVs Vulnerability Discovery via Log-Guided Fuzzing, 2021](https://www.usenix.org/system/files/sec21fall-aafer.pdf)
- [syzvegas: Beating Kernel Fuzzing Odds with Reinforcement Learning, 2021](https://www.usenix.org/system/files/sec21-wang-daimeng.pdf)
- [Agamotto: Accelerating Kernel Driver Fuzzing with Lightweight Virtual Machine Checkpoints, 2020](https://www.usenix.org/system/files/sec20-song.pdf)
- [FANS: Fuzzing Android Native System Services via Automated Interface Analysis, 2020](https://www.usenix.org/conference/usenixsecurity20/presentation/liu)
- [Analysis of DTLS Implementations Using Protocol State Fuzzing, 2020](https://www.usenix.org/conference/usenixsecurity20/presentation/fiterau-brostean)
- [EcoFuzz: Adaptive Energy-Saving Greybox Fuzzing as a Variant of the Adversarial Multi-Armed Bandit, 2020](https://www.usenix.org/conference/usenixsecurity20/presentation/yue)
- [Fuzzing Error Handling Code using Context-Sensitive Software Fault Injection, 2020](https://www.usenix.org/conference/usenixsecurity20/presentation/jiang)
- [FuzzGen: Automatic Fuzzer Generation, 2020](https://www.usenix.org/conference/usenixsecurity20/presentation/ispoglou)
- [ParmeSan: Sanitizer-guided Greybox Fuzzing, 2020](https://www.usenix.org/conference/usenixsecurity20/presentation/osterlund)
- [SpecFuzz: Bringing Spectre-type vulnerabilities to the surface, 2020](https://www.usenix.org/conference/usenixsecurity20/presentation/oleksenko)
- [FuzzGuard: Filtering out Unreachable Inputs in Directed Grey-box Fuzzing through Deep Learning, 2020](https://www.usenix.org/conference/usenixsecurity20/presentation/zong)
- [Montage: A Neural Network Language Model-Guided JavaScript Engine Fuzzer, 2020](https://www.usenix.org/conference/usenixsecurity20/presentation/lee-suyoung)
- [GREYONE: Data Flow Sensitive Fuzzing, 2020](https://www.usenix.org/conference/usenixsecurity20/presentation/gan)
- [Fuzzification: Anti-Fuzzing Techniques, 2019](https://www.usenix.org/conference/usenixsecurity19/presentation/jung)
- [AntiFuzz: Impeding Fuzzing Audits of Binary Executables, 2019](https://www.usenix.org/conference/usenixsecurity19/presentation/guler)
- [Charm: Facilitating Dynamic Analysis of Device Drivers of Mobile Systems, 2018](https://www.usenix.org/conference/usenixsecurity18/presentation/talebi)
- [MoonShine: Optimizing OS Fuzzer Seed Selection with Trace Distillation, 2018](https://www.usenix.org/conference/usenixsecurity18/presentation/pailoor)
- [QSYM : A Practical Concolic Execution Engine Tailored for Hybrid Fuzzing, 2018](https://www.usenix.org/conference/usenixsecurity18/presentation/yun)
- [OSS-Fuzz - Google's continuous fuzzing service for open source software, 2017](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/serebryany)
- [kAFL: Hardware-Assisted Feedback Fuzzing for OS Kernels, 2017](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/schumilo)
- [Protocol State Fuzzing of TLS Implementations, 2015](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/de-ruiter)
- [Optimizing Seed Selection for Fuzzing, 2014](https://softsec.kaist.ac.kr/~sangkilc/papers/rebert-usenixsec14.pdf)
- [Dowsing for overflows: a guided fuzzer to find buffer boundary violations, 2013](http://enigma.usenix.org/sites/default/files/sec13_proceedings_interior.pdf#page=57)
- [Fuzzing with Code Fragments, 2012](https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final73.pdf)


### ACM Conference on Computer and Communications Security (ACM CCS)
- [Snipuzz: Black-box Fuzzing of IoT Firmware via Message Snippet Inference, 2021](https://arxiv.org/pdf/2105.05445.pdf)
- [FREEDOM: Engineering a State-of-the-Art DOM Fuzzer, 2020](https://dl.acm.org/doi/abs/10.1145/3372297.3423340)
- [Intriguer: Field-Level Constraint Solving for Hybrid Fuzzing, 2019](https://dl.acm.org/citation.cfm?id=3354249)
- [Learning to Fuzz from Symbolic Execution with Application to Smart Contracts, 2019](https://files.sri.inf.ethz.ch/website/papers/ccs19-ilf.pdf)
- [Matryoshka: fuzzing deeply nested branches, 2019](https://web.cs.ucdavis.edu/~hchen/paper/chen2019matryoshka.pdf)
- [Evaluating Fuzz Testing, 2018](http://www.cs.umd.edu/~mwh/papers/fuzzeval.pdf)
- [Hawkeye: Towards a Desired Directed Grey-box Fuzzer, 2018](https://chenbihuan.github.io/paper/ccs18-chen-hawkeye.pdf)
- [IMF: Inferred Model-based Fuzzer, 2017](http://daramg.gift/paper/han-ccs2017.pdf)
- [SemFuzz: Semantics-based Automatic Generation of Proof-of-Concept Exploits, 2017](https://www.informatics.indiana.edu/xw7/papers/p2139-you.pdf)
- [AFL-based Fuzzing for Java with Kelinci, 2017](https://dl.acm.org/citation.cfm?id=3138820)
- [Designing New Operating Primitives to Improve Fuzzing Performance, 2017](http://iisp.gatech.edu/sites/default/files/images/designing_new_operating_primitives_to_improve_fuzzing_performance_vt.pdf)
- [Directed Greybox Fuzzing, 2017](https://dl.acm.org/citation.cfm?id=3134020)
- [SlowFuzz: Automated Domain-Independent Detection of Algorithmic Complexity Vulnerabilities, 2017](https://arxiv.org/pdf/1708.08437.pdf)
- [DIFUZE: Interface Aware Fuzzing for Kernel Drivers, 2017](https://acmccs.github.io/papers/p2123-corinaA.pdf)
- [Systematic Fuzzing and Testing of TLS Libraries, 2016](https://www.nds.rub.de/media/nds/veroeffentlichungen/2016/10/19/tls-attacker-ccs16.pdf)
- [Coverage-based Greybox Fuzzing as Markov Chain, 2016](https://ieeexplore.ieee.org/abstract/document/8233151)
- [eFuzz: A Fuzzer for DLMS/COSEM Electricity Meters, 2016](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.817.5616&rep=rep1&type=pdf)
- [Scheduling Black-box Mutational Fuzzing, 2013](https://softsec.kaist.ac.kr/~sangkilc/papers/woo-ccs13.pdf)
- [Taming compiler fuzzers, 2013](https://www.cs.utah.edu/~regehr/papers/pldi13.pdf)
- [SAGE: whitebox fuzzing for security testing, 2012](https://dl.acm.org/citation.cfm?id=2094081)
- [Grammar-based whitebox fuzzing, 2008](https://dl.acm.org/citation.cfm?id=1375607)
- [Taint-based directed whitebox fuzzing, 2009](https://dl.acm.org/citation.cfm?id=1555061)

### ArXiv (Fuzzing with Artificial Intelligence & Machine Learning, some interesting fuzzing topic, etc.)

- [Exposing Bugs in JavaScript Engines through Test Transplantation and Differential Testing, 2021 (with code)](https://arxiv.org/abs/2012.03759)
- [FuzzSplore: Visualizing Feedback-Driven Fuzzing Techniques, 2021 (with code)](https://arxiv.org/pdf/2102.02527.pdf)
- [AlphaFuzz: Evolutionary Mutation-based Fuzzing as Monte Carlo Tree Search, 2021](https://arxiv.org/pdf/2101.00612.pdf)
- [Fuzzing Hardware Like Software, 2021](https://arxiv.org/pdf/2102.02308.pdf)
- [HDR-Fuzz: Detecting Buffer Overruns using AddressSanitizer Instrumentation and Fuzzing, 2021](https://arxiv.org/pdf/2104.10466.pdf)
- [QFuzz: Quantitative Fuzzing for Side Channels, 2021 (with code)](https://arxiv.org/pdf/2106.03346.pdf)
- [CoCoFuzzing: Testing Neural Code Models with Coverage-Guided Fuzzing, 2021](https://arxiv.org/pdf/2106.09242.pdf)
- [MTFuzz: Fuzzing with a Multi-task Neural Network, 2020 (with code)](https://arxiv.org/pdf/2005.12392.pdf)
- [MEUZZ: Smart Seed Scheduling for Hybrid Fuzzing, 2020](https://arxiv.org/abs/2002.08568)
- [Semantic Fuzzing with Zest, 2019](https://arxiv.org/pdf/1812.00078.pdf)
- [A Review of Machine Learning Applications in Fuzzing, 2019](https://arxiv.org/abs/1906.11133)
- [Evolutionary Fuzzing of Android OS Vendor System Services, 2019](https://arxiv.org/abs/1906.00621)
- [MoonLight: Effective Fuzzing with Near-Optimal Corpus Distillation, 2019](https://arxiv.org/abs/1905.13055)
- [Coverage-Guided Fuzzing for Deep Neural Networks, 2018](https://arxiv.org/abs/1809.01266)
- [DLFuzz: Differential Fuzzing Testing of Deep Learning Systems, 2018](https://arxiv.org/abs/1808.09413)
- [TensorFuzz: Debugging Neural Networks with Coverage-Guided Fuzzing, 2018](https://arxiv.org/abs/1807.10875)
- [NEUZZ: Efficient Fuzzing with Neural Program Learning, 2018](https://arxiv.org/abs/1807.05620)
- [EnFuzz: From Ensemble Learning to Ensemble Fuzzing, 2018](https://arxiv.org/abs/1807.00182)
- [REST-ler: Automatic Intelligent REST API Fuzzing, 2018](https://arxiv.org/abs/1806.09739)
- [Deep Reinforcement Fuzzing, 2018](https://arxiv.org/abs/1801.04589)
- [Not all bytes are equal: Neural byte sieve for fuzzing, 2017](https://arxiv.org/abs/1711.04596)
- [Faster Fuzzing: Reinitialization with Deep Neural Models, 2017](https://arxiv.org/abs/1711.02807)
- [Learn&Fuzz: Machine Learning for Input Fuzzing, 2017](https://arxiv.org/abs/1701.07232)
- [Complementing Model Learning with Mutation-Based Fuzzing, 2016](https://arxiv.org/abs/1611.02429)

### The others (Including PLDI, OOPSLA, ICSE, TSE, ISSTA etc.)

- [Binary-level Directed Fuzzing for Use-After-Free Vulnerabilities, 2020 (TSE)](https://arxiv.org/pdf/2002.10751.pdf)
- [MemLock: Memory Usage Guided Fuzzing, 2020 (ICSE)](https://wcventure.github.io/pdf/ICSE2020_MemLock.pdf)
- [Magma: A Ground-Truth Fuzzing Benchmark, 2020 (ACM on Measurement and Analysis of Computing Systems)](https://hexhive.epfl.ch/magma/docs/preprint.pdf)
- [FuZZan: Efficient Sanitizer Metadata Design for Fuzzing, 2020 (USENIX ATC)](http://nebelwelt.net/files/20ATC.pdf)
- [The Art, Science, and Engineering of Fuzzing: A Survey, 2019 (TSE)](https://edmcman.github.io/papers/tse19.pdf)
- [Automated Conformance Testing for JavaScript Engines via Deep Compiler Fuzzing, 2021 (PLDI)](https://dl.acm.org/doi/abs/10.1145/3453483.3454054)
- [Typestate-Guided Fuzzer for Discovering Use-after-Free Vulnerabilities, 2020 (ICSE)](https://www.scedt.tees.ac.uk/s.qin/papers/icse2020-uafl.pdf)
- [Template-based Android Inter Process Communication Fuzzing, 2020 (International Conference on Availability, Reliability and Security)](https://faui1-files.cs.fau.de/public/publications/Template_based_Android_Inter_Process_Communication_Fuzzing.pdf)
- [DPIFuzz: A Differential Fuzzing Framework to Detect DPI Elusion Strategies for QUIC, 2020 (ACSAC)](https://publications.cispa.saarland/3220/1/DPIFuzz.pdf)
- [AFL++: Combining Incremental Steps of Fuzzing Research, 2020 (WOOT)](https://www.usenix.org/system/files/woot20-paper-fioraldi.pdf)
- [Parser-Directed Fuzzing, 2019 (PLDI)](https://pldi19.sigplan.org/track/pldi-2019-papers#)
- [Ifuzzer: An evolutionary interpreter fuzzer using genetic programming, 2016 (ESORICS)](https://www.cs.vu.nl/~herbertb/download/papers/ifuzzer-esorics16.pdf)
- [Hybrid fuzz testing: Discovering software bugs via fuzzing and symbolic execution, 2012 (School of Computer Science Carnegie Mellon University)](https://pdfs.semanticscholar.org/488a/b1e313f5109153f2c74e3b5d86d41e9b4b71.pdf)
- [Call-Flow Aware API Fuzz Testing for Security of Windows Systems, 2008 (International Conference on Computational Sciences and Its Applications)](https://www.computer.org/csdl/proceedings/iccsa/2008/3243/00/3243a019-abs.html)
- [Feedback-directed random test generation, 2007 (ICSE)](https://dl.acm.org/citation.cfm?id=1248841)



## Tools
Information about the various open source tools you can use to leverage fuzz testing.
### General-purpose
- [radamsa](https://gitlab.com/akihe/radamsa) - A general-purpose fuzzer.
- [zzuf](https://github.com/samhocevar/zzuf) - A transparent application input fuzzer.
### Binary
- [American fuzzy lop](http://lcamtuf.coredump.cx/afl/) - A security-oriented fuzzer that employs a novel type of compile-time instrumentation and genetic algorithms to automatically discover clean, interesting test cases that trigger new internal states in the targeted binary. 
- [WinAFL](https://github.com/googleprojectzero/winafl) - A fork of AFL for fuzzing Windows binaries.
- [libFuzzer](http://llvm.org/docs/LibFuzzer.html) - A library for coverage-guided fuzz testing. [Tutorial from Google.](https://github.com/google/fuzzer-test-suite/blob/master/tutorial/libFuzzerTutorial.md)
- [Driller](https://github.com/shellphish/driller) - An implementation of the [driller paper](https://www.cs.ucsb.edu/~vigna/publications/2016_NDSS_Driller.pdf). This implementation was built on top of AFL with angr being used as a symbolic tracer.
- [shellphish fuzzer](https://github.com/shellphish/fuzzer) - A Python interface to AFL, allowing for easy injection of testcases and other functionality.
- [Eclipser](https://github.com/SoftSec-KAIST/Eclipser) - A binary-based fuzz testing tool that improves upon classic coverage-based fuzzing by leveraging a novel technique called grey-box concolic testing.
- [Jazzer](https://github.com/CodeIntelligenceTesting/jazzer) - A coverage-guided, in-process fuzzer for the Java Virtual Machine. It is based on libFuzzer and can be applied directly to compiled applications.
### Web, JavaScript
- [jsfunfuzz](https://github.com/MozillaSecurity/funfuzz) - JavaScript engine fuzzers.
- [IFuzzer](https://github.com/vspandan/IFuzzer) - An Evolutionary Interpreter Fuzzer Using Genetic Programming.
- [domato](https://github.com/googleprojectzero/domato) - DOM fuzzer from [Google Project Zero](https://github.com/googleprojectzero). [Blog Post.](https://googleprojectzero.blogspot.com/2017/09/the-great-dom-fuzz-off-of-2017.html)
- [fuzzilli](https://github.com/googleprojectzero/fuzzilli) - A (coverage-)guided Javascript engine fuzzer, written by Samuel Groß.
- [CodeAlchemist](https://github.com/SoftSec-KAIST/CodeAlchemist) - JavaScript engine fuzzer, written by KAIST SoftSec Lab.
- [test-each](https://github.com/ehmicky/test-each) - Repeat tests using different inputs.
- [gremlins.js](https://github.com/marmelab/gremlins.js) - gremlins.js is a monkey testing library written in JavaScript.
### Network protocol
- [dtls-fuzzer](https://github.com/assist-project/dtls-fuzzer) - A Java tool which performs protocol state fuzzing of DTLS servers.
- [T-Fuzz](https://github.com/HexHive/T-Fuzz) - T-Fuzz leverages a coverage guided fuzzer to generate inputs.
- [TLS-Attacker](https://github.com/RUB-NDS/TLS-Attacker) - A Java-based framework for analyzing TLS libraries.
- [DELTA](https://github.com/seungsoo-lee/DELTA) - SDN Security evaluation framework.
- [boofuzz](https://github.com/jtpereyda/boofuzz) - Network Protocol Fuzzing for Humans. Documentation is available at http://boofuzz.readthedocs.io/, including nifty quickstart guides.
- [LL-Fuzzer](https://github.com/mit-ll/LL-Fuzzer) - An automated NFC fuzzing framework for Android devices.
- [tlsfuzzer](https://github.com/tomato42/tlsfuzzer) - A SSL and TLS protocol test suite and fuzzer.
- [TumbleRF](https://github.com/riverloopsec/tumblerf) - A framework that orchestrates the application of fuzzing techniques to RF systems. 
- [PULSAR](https://github.com/hgascon/pulsar) - A method for stateful black-box fuzzing of proprietary network protocols.
- [SPIKE](https://github.com/guilhermeferreira/spikepp/tree/master/SPIKE) - A fuzzer development framework like sulley, a predecessor of sulley.
- [PROTOS](https://www.ee.oulu.fi/roles/ouspg/Protos) - Security testing of protocol implementations.
### Driver
- [Charm](https://github.com/trusslab/charm) - A system solution that facilitates dynamic analysis of device drivers of mobile systems.
## Platform
- [certfuzz](https://github.com/CERTCC/certfuzz) - It contains the source code for the CMU CERT Basic Fuzzing Framework (BFF) and the CERT Failure Observation Engine (FOE).
- [Peach Fuzzer Platform](https://www.peach.tech/products/peach-fuzzer/) - An automated security testing platform that prevents zero day attacks by finding vulnerabilities in hardware and software systems.
- [Blackhat USA 2018 AFL workshop training materials](https://github.com/wrauner/afl-fuzzing-training) - From @wrauner at Samsung Research.
- [CI Fuzz](https://code-intelligence.com) - A CI/CD-agnostic platform for feedback-based fuzz testing of both native applications and Java web apps.

## Contribute

Contributions welcome! Read the [contribution guidelines](contributing.md) first.


## License

[![CC0](http://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](http://creativecommons.org/publicdomain/zero/1.0)

To the extent possible under law, cpuu has waived all copyright and
related or neighboring rights to this work.
