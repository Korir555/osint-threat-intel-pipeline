import React, { useState, useEffect } from 'react';
import './App.css';
import TargetScanner from './components/TargetScanner';
import TargetResults from './components/TargetResults';
import IndicatorViewer from './components/IndicatorViewer';
import TargetHistory from './components/TargetHistory';
import MispExporter from './components/MispExporter';

function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [scanResults, setScanResults] = useState(null);
  const [targets, setTargets] = useState([]);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  useEffect(() => {
    fetchTargets();
  }, [refreshTrigger]);

  const fetchTargets = async () => {
    try {
      const response = await fetch('http://localhost:5002/api/targets');
      const data = await response.json();
      setTargets(data);
    } catch (error) {
      console.error('Error fetching targets:', error);
    }
  };

  const handleScanComplete = (results) => {
    setScanResults(results);
    setActiveTab('results');
    setRefreshTrigger(prev => prev + 1);
  };

  return (
    <div className="app">
      <header className="header">
        <div className="header-content">
          <h1>🔍 OSINT & Threat Intelligence Pipeline</h1>
          <p>Automated Reconnaissance | Domain Intelligence | Threat Indicator Extraction</p>
        </div>
      </header>

      <nav className="nav-tabs">
        <button
          className={`tab ${activeTab === 'scanner' ? 'active' : ''}`}
          onClick={() => setActiveTab('scanner')}
        >
          Scan Target
        </button>
        <button
          className={`tab ${activeTab === 'results' ? 'active' : ''}`}
          onClick={() => setActiveTab('results')}
        >
          Scan Results
        </button>
        <button
          className={`tab ${activeTab === 'history' ? 'active' : ''}`}
          onClick={() => setActiveTab('history')}
        >
          Target History
        </button>
        <button
          className={`tab ${activeTab === 'indicators' ? 'active' : ''}`}
          onClick={() => setActiveTab('indicators')}
        >
          Threat Indicators
        </button>
        <button
          className={`tab ${activeTab === 'export' ? 'active' : ''}`}
          onClick={() => setActiveTab('export')}
        >
          MISP Export
        </button>
      </nav>

      <main className="main-content">
        {activeTab === 'scanner' && (
          <TargetScanner onScanComplete={handleScanComplete} />
        )}
        
        {activeTab === 'results' && scanResults && (
          <TargetResults results={scanResults} />
        )}
        
        {activeTab === 'history' && (
          <TargetHistory targets={targets} />
        )}
        
        {activeTab === 'indicators' && <IndicatorViewer />}
        
        {activeTab === 'export' && (
          <MispExporter targets={targets} />
        )}
      </main>

      <footer className="footer">
        <p>Project #24: OSINT & Threat Intelligence Pipeline | Built for Security Research & UN/NGO</p>
        <p>GitHub: <a href="https://github.com/Korir555/osint-threat-intel-pipeline" target="_blank">Korir555/osint-threat-intel-pipeline</a></p>
      </footer>
    </div>
  );
}

export default App;
