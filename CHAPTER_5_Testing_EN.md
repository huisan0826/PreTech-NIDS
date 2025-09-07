# CHAPTER 5

## 5.1 Introduction

This chapter presents a comprehensive testing framework for the PreTech-NIDS (PreTech Network Intrusion Detection System) project. The testing phase is crucial for validating the system's functionality, usability, and overall performance before deployment. This chapter outlines the testing methodologies employed, the design of testing templates, and the execution plan to ensure the system meets the intended requirements and user expectations.

The testing approach focuses on two primary evaluation techniques: User Acceptance Testing (UAT) and System Usability Scale (SUS) testing. These methodologies were selected to provide both functional validation and quantitative usability assessment, ensuring that the system not only performs as designed but also delivers an optimal user experience for network security professionals.

## 5.2 Testing Design / Plan

### 5.2.1 Selected Testing Techniques

#### 5.2.1.1 User Acceptance Testing (UAT)

User Acceptance Testing was chosen as the primary functional testing methodology because it validates whether the system meets the business requirements and user expectations. UAT ensures that the system performs correctly in real-world scenarios and that all critical functionalities work as intended from the end-user perspective. This methodology provides comprehensive validation of core system functionality against specified requirements, verification of user interface and interaction workflows, and ensures that system performance meets operational standards. Additionally, UAT serves to identify any functional gaps or usability issues while confirming system readiness for production deployment.

The testing scope encompasses user registration and authentication processes, real-time network monitoring capabilities, PCAP file analysis functionality, report generation and management features, user permission and access control systems, and alert system and notification mechanisms. This comprehensive coverage ensures that all critical aspects of the PreTech-NIDS system are thoroughly evaluated from the end-user perspective, providing confidence in the system's operational readiness.

#### 5.2.1.2 System Usability Scale (SUS)

The System Usability Scale was selected as the quantitative usability assessment tool because it provides a standardized, reliable method for measuring system usability. SUS is widely recognized in the industry and offers objective metrics for comparing usability across different systems and versions. This methodology quantifies overall system usability through standardized metrics, identifies specific usability issues and improvement areas, and provides baseline measurements for future system enhancements. Furthermore, SUS enables comparison with industry standards and benchmarks while supporting data-driven usability improvement decisions.

The assessment areas cover overall system usability and user satisfaction, learning curve and ease of use, interface design and navigation, system performance and responsiveness, and user confidence and recommendation likelihood. This comprehensive evaluation framework ensures that the system's usability is measured across multiple dimensions, providing actionable insights for system improvement.

### 5.2.2 Testing Template Design

#### 5.2.2.1 UAT Testing Template

The UAT template was designed to systematically evaluate each major system component through structured test scenarios. The template structure includes a test information section that captures tester details, test environment, and session information, along with scenario-based testing featuring six comprehensive test scenarios covering all major system functions. The template incorporates an expected versus actual results framework that provides structured comparison for each test case, along with issue tracking that offers a standardized format for documenting problems and their severity levels. Additionally, the template includes assessment metrics with a quantitative scoring system for functionality and user experience, and a feature evaluation table using a 5-point rating scale for individual system features.

The six test scenarios encompass user registration and login for authentication system validation, real-time network monitoring for live traffic analysis and detection capabilities, PCAP file analysis for offline packet capture file processing, report viewing and management for historical data access and reporting, user permission management for role-based access control validation, and alert system for notification and alert management functionality. This comprehensive coverage ensures that all critical aspects of the PreTech-NIDS system are thoroughly evaluated through structured testing procedures.

#### 5.2.2.2 SUS Testing Template

The SUS template follows the standardized 10-question format with additional assessment components designed to provide comprehensive usability evaluation. The template components include standard SUS questions featuring 10 validated questions using a 5-point Likert scale, detailed feedback sections with open-ended questions for qualitative insights, and function-specific assessment providing targeted evaluation of interface, operations, and performance. The template also incorporates a scoring framework with an automated calculation system for SUS scores and usability levels, along with usability level classification offering clear categorization into Excellent, Good, Average, and Poor levels.

This comprehensive template structure ensures that both quantitative and qualitative aspects of system usability are captured, providing a complete picture of the user experience and identifying specific areas for improvement. The combination of standardized questions and detailed feedback sections allows for both statistical analysis and in-depth understanding of user perceptions and experiences with the PreTech-NIDS system.

### 5.2.3 Target Audience and Execution Plan

#### 5.2.3.1 Target Audience Selection

The primary test participants consist of four qualified professionals representing different user roles and expertise areas. Network Security Analysts, comprising two participants, are professionals with expertise in network security and intrusion detection systems who will provide insights from the primary user perspective. System Administrators, represented by one participant, are IT professionals responsible for system deployment and maintenance who will evaluate the system from an operational standpoint. Network Engineers, also represented by one participant, are technical specialists with network infrastructure knowledge who will assess the system's technical implementation and performance.

The selection criteria require a minimum of three years of experience in cybersecurity or network administration, familiarity with network monitoring and intrusion detection concepts, ability to independently operate system interfaces, and willingness to provide detailed feedback and participate in follow-up discussions. This diverse group of participants ensures comprehensive evaluation from multiple perspectives, covering both technical and operational aspects of the PreTech-NIDS system.

#### 5.2.3.2 Testing Execution Framework

The testing execution framework is structured into four distinct phases to ensure systematic and comprehensive evaluation. Phase 1 focuses on preparation and setup, involving test environment configuration and validation, test data preparation and user account creation, tester training and orientation sessions, and template distribution and instruction provision. This foundational phase ensures that all participants are properly prepared and that the testing environment is optimally configured for accurate evaluation.

Phase 2 encompasses UAT execution, featuring individual scenario testing by assigned testers, real-time issue documentation and severity assessment, functional validation against specified requirements, and performance evaluation under realistic conditions. Phase 3 involves SUS assessment, including independent system usage sessions lasting 30-45 minutes per tester, SUS questionnaire completion with detailed feedback, function-specific usability evaluation, and overall satisfaction and recommendation assessment. Phase 4 focuses on results compilation and analysis, covering data collection and validation from all testers, statistical analysis of SUS scores and UAT results, issue prioritization and resolution planning, and final assessment and recommendation generation.

### 5.2.4 Testing Environment and Prerequisites

#### 5.2.4.1 Technical Requirements

The system environment requirements include Windows 10/11 operating system, minimum 16GB RAM with Intel i7 processor, Chrome/Firefox browser in latest versions, and stable network connectivity for real-time monitoring. These specifications ensure optimal performance during testing and provide a realistic environment that mirrors typical production conditions. The software dependencies encompass Python 3.8+ runtime environment, MongoDB database system, TensorFlow and scikit-learn libraries, and PreTech-NIDS application deployment. This comprehensive software stack supports all system functionalities and provides the necessary infrastructure for thorough testing evaluation.

#### 5.2.4.2 Test Data Preparation

The test data preparation involves comprehensive collection of PCAP test files including normal network traffic samples, DDoS attack simulation data, port scanning attack patterns, and malware communication samples. This diverse dataset ensures that the system's detection capabilities are thoroughly evaluated across various threat scenarios and normal operational conditions. User accounts are prepared with multiple role-based test accounts including Admin, Analyst, and Viewer roles, each with pre-configured permissions and access levels, along with appropriate test data for each user role. This preparation ensures that all system functionalities can be properly tested from different user perspectives and permission levels.

### 5.2.5 Success Criteria and Acceptance Standards

#### 5.2.5.1 UAT Success Criteria

The UAT success criteria encompass both functional requirements and performance standards to ensure comprehensive system validation. The functional requirements include all critical system functions being operational without errors, user authentication and authorization working correctly, real-time monitoring and detection functioning properly, report generation and data export capabilities working effectively, and alert system responding appropriately to threats. These requirements ensure that the core functionality of the PreTech-NIDS system operates as designed and meets the specified business objectives.

The performance standards establish measurable benchmarks including system response time under 3 seconds for standard operations, PCAP file processing completed within acceptable timeframes, real-time monitoring maintaining stable performance, and user interface being responsive and intuitive. These standards ensure that the system not only functions correctly but also delivers acceptable performance levels that meet user expectations and operational requirements.

#### 5.2.5.2 SUS Success Criteria

The SUS success criteria define specific usability thresholds and quality metrics to ensure optimal user experience. The usability thresholds include an average SUS score of at least 70 points representing the Good level, minimum 75% of testers providing positive feedback, key functionality usability rating of at least 7 out of 10, and overall user satisfaction of at least 75%. These thresholds establish clear benchmarks for acceptable usability levels and ensure that the system meets industry standards for user experience.

The quality metrics encompass learning curve completion within 30 minutes, error rate below 10% for standard operations, user confidence level of at least 7 out of 10, and recommendation likelihood of at least 70%. These metrics provide additional validation of the system's usability and ensure that users can effectively learn and operate the system while maintaining high confidence levels and satisfaction.

## 5.4 Summary

This chapter has outlined a comprehensive testing framework for the PreTech-NIDS project, incorporating two complementary testing methodologies: User Acceptance Testing (UAT) and System Usability Scale (SUS) testing. The testing design ensures thorough validation of both functional requirements and usability standards. The key testing components include a UAT framework featuring six comprehensive test scenarios covering all major system functionalities, SUS assessment providing standardized usability evaluation with quantitative metrics, target audience comprising four qualified professionals representing different user roles, and execution plan following a structured four-phase approach ensuring systematic evaluation.

The testing framework is designed to validate that the PreTech-NIDS system meets both functional and usability requirements, providing confidence in the system's readiness for production deployment. The combination of UAT and SUS testing ensures comprehensive evaluation from both technical and user experience perspectives. The expected outcomes include detailed UAT results with issue tracking and resolution status, quantitative SUS scores with usability level classification, comprehensive feedback and improvement recommendations, and final assessment report with deployment recommendations.

The testing phase represents a critical milestone in the PreTech-NIDS development lifecycle, ensuring that the system delivers both the required functionality and an optimal user experience for network security professionals. This comprehensive approach to testing validation provides the necessary confidence for system deployment while identifying areas for future improvement and enhancement.
