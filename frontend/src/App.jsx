import { useState } from 'react'
import Sidebar from './components/Sidebar.jsx'
import HeadersChecker from './components/HeadersChecker.jsx'
import PhishingAnalyzer from './components/PhishingAnalyzer.jsx'

export default function App() {
  const [active, setActive] = useState('headers')

  return (
    <div className="min-h-screen flex text-ink font-body">
      <Sidebar active={active} onSelect={setActive} />
      <main className="flex-1 px-8 py-10 overflow-y-auto">
        {active === 'headers' ? <HeadersChecker /> : <PhishingAnalyzer />}
      </main>
    </div>
  )
}
