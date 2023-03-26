# Development Roadmap:

[Phase 1](): AI Controlled Data Source (input) Processing:

1. Preselection of Data Source/Inputsto process:
    - System Logs
    - System Scans
    - System Properties
    - Custom System Properties
2. Categorizing events in the data source (input)
3. Calculating severity level to every event
4. Defining final weights/confidence values
5. Defining values for:
    - Context Aware Event Severity Risk Layer 1
    - Context Aware Event Severity Risk Layer 2
6. Localization of the system:
    - Centralized Cloud
    - Centralized On Premises
    - Decentralized (every agent calculates scores)

[Phase 2](): AI Controlled Response

1. Defining actions to perform for every event based on the score:
    - Developing LLM Specific (Transformers) Model for security data
    - Developing Set Of Complementary Rules for AI Decision Process
2. Engineering actions (AI Control Over Infrastructure)