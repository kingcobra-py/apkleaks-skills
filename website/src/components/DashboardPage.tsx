import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Badge,
  Button,
  Card,
  Col,
  InputNumber,
  Modal,
  Progress,
  Row,
  Space,
  Table,
  Tag,
  Typography,
  Alert,
  message,
} from 'antd';
import {
  CloudDownloadOutlined,
  ThunderboltOutlined,
  SecurityScanOutlined,
  ApiOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  SyncOutlined,
  DownloadOutlined,
  DashboardOutlined,
  HddOutlined,
  DeleteOutlined,
  RetweetOutlined,
  PauseCircleOutlined,
  PlayCircleOutlined,
} from '@ant-design/icons';
import { motion } from 'framer-motion';

const { Title, Paragraph, Text } = Typography;

type LogLine = { ts: string; level: string; message: string };
type Job = {
  apk: string;
  ok: boolean;
  finding_count?: number;
  has_critical?: boolean;
  duration_ms?: number;
  hits?: { aws?: boolean; sendgrid?: boolean; stripe?: boolean };
  error?: string;
  raw_lines?: string[];
  priority_lines?: string[];
  other_lines?: string[];
  aws_pairs?: string[];
};
type Config = {
  threads?: number;
  download_count?: number;
  download_workers?: number;
  loop_enabled?: boolean;
  loop_apps?: number;
  loop_threads?: number;
  loop_download_workers?: number;
};
type LoopStatus = {
  enabled?: boolean;
  running?: boolean;
  state?: string;
  phase?: string;
  cycle?: number;
  apps?: number;
  threads?: number;
  download_workers?: number;
  message?: string;
};
type SystemStats = {
  cpu_percent?: number;
  memory?: {
    percent?: number;
    used_gb?: number;
    total_gb?: number;
  };
  apk_count?: number;
  download_running?: boolean;
  scan_running?: boolean;
  loop_running?: boolean;
  loop?: LoopStatus;
  config?: Config;
};
type ActiveApp = {
  apk: string;
  phase: string;
  percent: number;
  message: string;
  elapsed_ms?: number;
  started_at?: string;
};
type Status = {
  ok: boolean;
  demo?: boolean;
  state: string;
  threads?: number;
  input_dir?: string;
  output_dir?: string;
  started_at?: string;
  updated_at?: string;
  finished_at?: string | null;
  progress: { total: number; completed: number; succeeded: number; failed: number; percent: number };
  counts: {
    findings: number;
    critical: number;
    high: number;
    has_aws: number;
    has_sendgrid: number;
    has_stripe: number;
  };
  current: string[];
  active?: Record<string, ActiveApp>;
  jobs: Job[];
  logs: LogLine[];
  raw_lines?: string[];
  priority_lines?: string[];
  other_lines?: string[];
  aws_pairs?: string[];
  system?: SystemStats;
  config?: Config;
  loop?: LoopStatus;
};

const PHASE_COLOR: Record<string, string> = {
  queued: '#64748b',
  starting: '#38bdf8',
  integrity: '#22d3ee',
  decompiling: '#818cf8',
  scanning: '#f59e0b',
  classifying: '#a78bfa',
  done: '#10b981',
  failed: '#ef4444',
};

const DEMO: Status = {
  ok: true,
  demo: true,
  state: 'running',
  threads: 4,
  input_dir: 'apks',
  output_dir: 'results',
  started_at: '2026-07-29T21:00:00+00:00',
  updated_at: '2026-07-29T21:12:40+00:00',
  finished_at: null,
  progress: { total: 100, completed: 42, succeeded: 40, failed: 2, percent: 42 },
  counts: { findings: 3, critical: 1, high: 2, has_aws: 1, has_sendgrid: 0, has_stripe: 1 },
  current: ['org.example.app.apk', 'com.demo.wallet.apk'],
  active: {
    'org.example.app.apk': {
      apk: 'org.example.app.apk',
      phase: 'decompiling',
      percent: 45,
      message: 'Decompiling with jadx (this can take a while)',
      elapsed_ms: 18200,
    },
    'com.demo.wallet.apk': {
      apk: 'com.demo.wallet.apk',
      phase: 'scanning',
      percent: 72,
      message: 'Scanning files 3600/5000',
      elapsed_ms: 9400,
    },
  },
  jobs: [],
  logs: [{ ts: '2026-07-29T21:00:01+00:00', level: 'info', message: 'Discovered 100 APK(s); threads=4' }],
  raw_lines: [
    'AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    'example_other_api_token_value_123456',
  ],
  aws_pairs: ['AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'],
  system: {
    cpu_percent: 12.5,
    memory: { percent: 18.2, used_gb: 22.1, total_gb: 125 },
    apk_count: 99,
    download_running: false,
    scan_running: true,
    config: { threads: 4, download_count: 100, download_workers: 10, loop_apps: 100, loop_threads: 12 },
  },
};

const monoBoxStyle: React.CSSProperties = {
  fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
  fontSize: 12,
  lineHeight: 1.7,
  maxHeight: 280,
  overflow: 'auto',
  background: '#020617',
  color: '#e2e8f0',
  padding: 16,
  borderRadius: 8,
  border: '1px solid #1e293b',
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-all',
};

const apiBaseCandidates = [''];

async function apiFetch(path: string, init?: RequestInit, timeoutMs = 4000): Promise<Response | null> {
  for (const base of apiBaseCandidates) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(`${base}${path}`, {
        cache: 'no-store',
        ...init,
        signal: controller.signal,
      });
      if (res.ok || res.status < 500) return res;
    } catch {
      // try next / timeout
    } finally {
      window.clearTimeout(timer);
    }
  }
  return null;
}

const DashboardPage: React.FC = () => {
  const [status, setStatus] = useState<Status | null>(null);
  const [source, setSource] = useState<'loading' | 'demo' | 'live'>('loading');
  const [downloadCount, setDownloadCount] = useState<number>(100);
  const [downloadWorkers, setDownloadWorkers] = useState<number>(10);
  const [threads, setThreads] = useState<number>(4);
  const [loopApps, setLoopApps] = useState<number>(100);
  const [loopThreads, setLoopThreads] = useState<number>(12);
  const [loopDownloadWorkers, setLoopDownloadWorkers] = useState<number>(10);
  const [busyDownload, setBusyDownload] = useState(false);
  const [busyClear, setBusyClear] = useState(false);
  const [busyThreads, setBusyThreads] = useState(false);
  const [busyLoop, setBusyLoop] = useState(false);
  const [priorityLines, setPriorityLines] = useState<string[]>([]);
  const [otherLines, setOtherLines] = useState<string[]>([]);
  const sawLiveRef = useRef(false);
  const formSeededRef = useRef(false);

  const seedFormFromConfig = useCallback((cfg?: Config | null, threadsFallback?: number) => {
    if (!cfg && threadsFallback == null) return;
    if (cfg?.download_count) setDownloadCount(cfg.download_count);
    if (cfg?.download_workers) setDownloadWorkers(cfg.download_workers);
    if (cfg?.threads) setThreads(cfg.threads);
    else if (threadsFallback) setThreads(threadsFallback);
    if (cfg?.loop_apps) setLoopApps(cfg.loop_apps);
    if (cfg?.loop_threads) setLoopThreads(cfg.loop_threads);
    if (cfg?.loop_download_workers) setLoopDownloadWorkers(cfg.loop_download_workers);
    else if (cfg?.download_workers) setLoopDownloadWorkers(cfg.download_workers);
  }, []);

  const applyDemo = useCallback(() => {
    setStatus(DEMO);
    setSource('demo');
    setPriorityLines([
      'AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    ]);
    setOtherLines(['example_other_api_token_value_123456']);
    // Demo may re-seed form; allow a later live response to seed once.
    formSeededRef.current = false;
    seedFormFromConfig(DEMO.system?.config, DEMO.threads);
  }, [seedFormFromConfig]);

  const refresh = useCallback(async (opts?: { results?: boolean }) => {
    const wantResults = opts?.results !== false;
    const res = await apiFetch('/api/status', undefined, 3500);
    if (!res || !res.ok) {
      // Never flash demo secrets over a live session if the API blips.
      if (!sawLiveRef.current) applyDemo();
      return;
    }
    const data = (await res.json()) as Status;
    if (!data?.progress) return;
    const isDemo = Boolean(data.demo);
    if (!isDemo) sawLiveRef.current = true;
    setStatus(data);
    setSource(isDemo ? 'demo' : 'live');
    // Seed inputs once from server config — never overwrite while the user is typing.
    if (!isDemo && !formSeededRef.current) {
      seedFormFromConfig(data.config || data.system?.config, data.threads);
      formSeededRef.current = true;
    }

    // Prefer lines already on status (fast). Only hit /api/results occasionally.
    let nextPriority = Array.isArray(data.priority_lines) ? data.priority_lines : null;
    let nextOther = Array.isArray(data.other_lines) ? data.other_lines : null;
    if (wantResults) {
      const resultsRes = await apiFetch('/api/results', undefined, 6000);
      if (resultsRes?.ok) {
        const agg = await resultsRes.json();
        if (Array.isArray(agg?.priority_lines)) nextPriority = agg.priority_lines;
        if (Array.isArray(agg?.other_lines)) nextOther = agg.other_lines;
      }
    }
    if (nextPriority !== null) setPriorityLines(nextPriority);
    if (nextOther !== null) setOtherLines(nextOther);
  }, [applyDemo, seedFormFromConfig]);

  useEffect(() => {
    let cancelled = false;
    let tickN = 0;
    const tick = async () => {
      if (cancelled) return;
      tickN += 1;
      // Full results merge every ~10s; status every 2s.
      await refresh({ results: tickN === 1 || tickN % 5 === 0 });
    };
    tick();
    const id = window.setInterval(tick, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [refresh]);

  const view = status ?? DEMO;

  const onDownload = async () => {
    setBusyDownload(true);
    try {
      const res = await apiFetch('/api/download', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ count: downloadCount, workers: downloadWorkers }),
      });
      const data = res ? await res.json() : null;
      if (!res || !data?.ok) {
        message.error(data?.error || 'Download failed to start');
      } else {
        message.success(data.message || `Downloading ${downloadCount} APKs`);
      }
      await refresh();
    } finally {
      setBusyDownload(false);
    }
  };

  const onClearApks = () => {
    Modal.confirm({
      title: 'Remove downloaded APKs?',
      content:
        'Deletes every .apk in the download folder. Scan results (Priority / Other) are kept. Packages already scanned stay skipped on the next download.',
      okText: 'Delete APKs',
      okButtonProps: { danger: true },
      cancelText: 'Cancel',
      onOk: async () => {
        setBusyClear(true);
        try {
          const res = await apiFetch('/api/apks/clear', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({}),
          });
          const data = res ? await res.json() : null;
          if (!res || !data?.ok) {
            message.error(data?.error || 'Failed to remove APKs');
          } else {
            message.success(data.message || `Removed ${data.removed ?? 0} APKs`);
          }
          await refresh();
        } finally {
          setBusyClear(false);
        }
      },
    });
  };

  const onApplyThreads = async () => {
    setBusyThreads(true);
    try {
      const res = await apiFetch('/api/threads', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threads, restart: true }),
      });
      const data = res ? await res.json() : null;
      if (!res || !data?.ok) {
        message.error(data?.error || 'Failed to update threads');
      } else {
        message.success(data.message || `Scan restarted with ${threads} threads`);
      }
      await refresh();
    } finally {
      setBusyThreads(false);
    }
  };

  const onStartLoop = async () => {
    setBusyLoop(true);
    try {
      const res = await apiFetch('/api/loop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          apps: loopApps,
          threads: loopThreads,
          download_workers: loopDownloadWorkers,
        }),
      });
      const data = res ? await res.json() : null;
      if (!res || !data?.ok) {
        message.error(data?.error || 'Failed to start loop');
      } else {
        message.success(data.message || 'Auto loop started');
      }
      await refresh();
    } finally {
      setBusyLoop(false);
    }
  };

  const onStopLoop = async () => {
    setBusyLoop(true);
    try {
      const res = await apiFetch('/api/loop/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const data = res ? await res.json() : null;
      if (!res || !data?.ok) {
        message.error(data?.error || 'Failed to stop loop');
      } else {
        message.success(data.message || 'Loop stop requested');
      }
      await refresh();
    } finally {
      setBusyLoop(false);
    }
  };

  const downloadText = (filename: string, text: string) => {
    const body = text.endsWith('\n') || !text ? text : `${text}\n`;
    const blob = new Blob([body], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const onExportPriority = async () => {
    const res = await apiFetch('/api/results/priority.txt');
    let text = priorityLines.join('\n');
    if (res?.ok) text = await res.text();
    downloadText('priority-results.txt', text);
  };

  const onExportOther = async () => {
    const res = await apiFetch('/api/results/other.txt');
    let text = otherLines.join('\n');
    if (res?.ok) text = await res.text();
    downloadText('other-apis-results.txt', text);
  };

  const stateColor = view.state === 'completed' ? 'success' : view.state === 'running' ? 'processing' : 'default';
  const sys = view.system;
  const cpu = sys?.cpu_percent ?? 0;
  const mem = sys?.memory?.percent ?? 0;
  const loop = view.loop || sys?.loop;
  const loopRunning = Boolean(loop?.running || sys?.loop_running);
  const activeApps = useMemo(() => {
    const map = view.active || {};
    const list = Object.values(map);
    if (list.length) return list.sort((a, b) => (b.elapsed_ms || 0) - (a.elapsed_ms || 0));
    // Fallback for older status.json without active map
    return (view.current || []).map((apk) => ({
      apk,
      phase: 'scanning',
      percent: 50,
      message: 'Working…',
      elapsed_ms: 0,
    }));
  }, [view.active, view.current]);

  const columns = useMemo(
    () => [
      {
        title: 'APK',
        dataIndex: 'apk',
        key: 'apk',
        render: (v: string) => <Text code>{v}</Text>,
      },
      {
        title: 'Status',
        dataIndex: 'ok',
        key: 'ok',
        width: 100,
        render: (ok: boolean) =>
          ok ? (
            <Tag icon={<CheckCircleOutlined />} color="success">
              ok
            </Tag>
          ) : (
            <Tag icon={<CloseCircleOutlined />} color="error">
              failed
            </Tag>
          ),
      },
      {
        title: 'Secrets',
        key: 'secrets',
        width: 120,
        render: (_: unknown, row: Job) => {
          const total = row.finding_count ?? 0;
          const pri = (row.priority_lines || []).length;
          const other = (row.other_lines || []).length || Math.max(0, total - pri);
          if (!total) return '—';
          return (
            <Space size={4} wrap>
              {pri ? <Tag color="orange">P {pri}</Tag> : null}
              {other ? <Tag>O {other}</Tag> : null}
              {!pri && !other ? <Tag>{total}</Tag> : null}
            </Space>
          );
        },
      },
      {
        title: 'Duration',
        dataIndex: 'duration_ms',
        key: 'duration_ms',
        width: 100,
        render: (ms?: number) => (ms != null ? `${(ms / 1000).toFixed(1)}s` : '—'),
      },
    ],
    [],
  );

  return (
    <div className="dashboard-page" style={{ padding: '32px 24px', maxWidth: 1200, margin: '0 auto' }}>
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
        <Space align="center" style={{ marginBottom: 8 }} wrap>
          <Title level={2} style={{ margin: 0, color: '#e2e8f0' }}>
            Batch Scan Dashboard
          </Title>
          <Badge status={stateColor as 'success' | 'processing' | 'default'} text={view.state.toUpperCase()} />
          <Tag color={source === 'live' ? 'green' : source === 'loading' ? 'default' : 'gold'}>
            {source === 'live' ? 'LIVE' : source === 'loading' ? 'LOADING' : 'DEMO'}
          </Tag>
          {sys?.download_running ? <Tag color="blue">DOWNLOADING</Tag> : null}
          {sys?.scan_running ? <Tag color="cyan">SCANNING</Tag> : null}
          {loopRunning ? <Tag color="purple">LOOP CYCLE {loop?.cycle ?? ''}</Tag> : null}
        </Space>
        <Paragraph type="secondary" style={{ maxWidth: 760 }}>
          Download unique F-Droid APKs in parallel, control scan threads, run an automatic download→scan
          loop, and export raw secrets (AWS as <Text code>AwsKey:AwsSecretKey</Text>).
        </Paragraph>
      </motion.div>

      {source === 'demo' && (
        <Alert
          style={{ marginBottom: 20 }}
          type="info"
          showIcon
          message="Showing demo data"
          description="Start the dashboard API on the VPS to switch to LIVE status and controls."
        />
      )}
      {source === 'loading' && (
        <Alert
          style={{ marginBottom: 20 }}
          type="info"
          showIcon
          message="Connecting to scan API…"
          description="Priority and Other results load from the live results store — demo secrets are not shown."
        />
      )}

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={24} md={8}>
          <Card className="glass-card" title={<Space><CloudDownloadOutlined /> Download APKs</Space>}>
            <Space direction="vertical" style={{ width: '100%' }} size="middle">
              <div>
                <Text type="secondary">Number of new APKs (skips packages already downloaded or scanned)</Text>
                <InputNumber
                  min={1}
                  max={5000}
                  value={downloadCount}
                  onChange={(v) => setDownloadCount(Number(v || 1))}
                  style={{ width: '100%', marginTop: 8 }}
                />
              </div>
              <div>
                <Text type="secondary">Download threads (parallel at once)</Text>
                <InputNumber
                  min={1}
                  max={32}
                  value={downloadWorkers}
                  onChange={(v) => setDownloadWorkers(Number(v || 1))}
                  style={{ width: '100%', marginTop: 8 }}
                />
              </div>
              <Button type="primary" block loading={busyDownload} icon={<CloudDownloadOutlined />} onClick={onDownload}>
                Start download
              </Button>
              <Button
                danger
                block
                loading={busyClear}
                icon={<DeleteOutlined />}
                onClick={onClearApks}
                disabled={Boolean(sys?.download_running || sys?.scan_running || loopRunning)}
              >
                Remove downloaded APKs
              </Button>
              <Text type="secondary">On disk: {sys?.apk_count ?? '—'} APKs</Text>
            </Space>
          </Card>
        </Col>
        <Col xs={24} md={8}>
          <Card className="glass-card" title={<Space><ThunderboltOutlined /> Scan threads</Space>}>
            <Space direction="vertical" style={{ width: '100%' }} size="middle">
              <div>
                <Text type="secondary">Worker threads (1–32)</Text>
                <InputNumber
                  min={1}
                  max={32}
                  value={threads}
                  onChange={(v) => setThreads(Number(v || 1))}
                  style={{ width: '100%', marginTop: 8 }}
                />
              </div>
              <Button
                type="primary"
                block
                loading={busyThreads}
                icon={<ThunderboltOutlined />}
                onClick={onApplyThreads}
                disabled={loopRunning}
              >
                Apply & restart scan
              </Button>
              <Text type="secondary">Active setting: {view.threads ?? threads}</Text>
            </Space>
          </Card>
        </Col>
        <Col xs={24} md={8}>
          <Card className="glass-card" title={<Space><DashboardOutlined /> System</Space>}>
            <Space direction="vertical" style={{ width: '100%' }} size="middle">
              <div>
                <Text type="secondary">CPU</Text>
                <Progress percent={Math.min(100, Number(cpu) || 0)} status="active" strokeColor="#06b6d4" />
              </div>
              <div>
                <Text type="secondary">
                  <HddOutlined /> RAM {sys?.memory?.used_gb ?? '—'} / {sys?.memory?.total_gb ?? '—'} GB
                </Text>
                <Progress percent={Math.min(100, Number(mem) || 0)} strokeColor="#38bdf8" />
              </div>
            </Space>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={24}>
          <Card
            className="glass-card"
            title={
              <Space>
                <RetweetOutlined spin={loopRunning} />
                Auto loop cycle
                {loopRunning ? <Tag color="purple">RUNNING</Tag> : <Tag>IDLE</Tag>}
                {loop?.cycle ? <Tag color="processing">cycle {loop.cycle}</Tag> : null}
              </Space>
            }
          >
            <Paragraph type="secondary" style={{ marginTop: 0 }}>
              Automatically downloads a batch, scans it, then repeats. Set apps per cycle, scan threads, and
              parallel download workers.
            </Paragraph>
            <Row gutter={[16, 16]}>
              <Col xs={24} md={8}>
                <Text type="secondary">Apps per cycle</Text>
                <InputNumber
                  min={1}
                  max={5000}
                  value={loopApps}
                  onChange={(v) => setLoopApps(Number(v || 1))}
                  style={{ width: '100%', marginTop: 8 }}
                  disabled={loopRunning}
                />
              </Col>
              <Col xs={24} md={8}>
                <Text type="secondary">Scan threads</Text>
                <InputNumber
                  min={1}
                  max={32}
                  value={loopThreads}
                  onChange={(v) => setLoopThreads(Number(v || 1))}
                  style={{ width: '100%', marginTop: 8 }}
                  disabled={loopRunning}
                />
              </Col>
              <Col xs={24} md={8}>
                <Text type="secondary">Download threads</Text>
                <InputNumber
                  min={1}
                  max={32}
                  value={loopDownloadWorkers}
                  onChange={(v) => setLoopDownloadWorkers(Number(v || 1))}
                  style={{ width: '100%', marginTop: 8 }}
                  disabled={loopRunning}
                />
              </Col>
            </Row>
            <Space wrap style={{ marginTop: 16 }}>
              <Button
                type="primary"
                loading={busyLoop}
                icon={<PlayCircleOutlined />}
                onClick={onStartLoop}
                disabled={loopRunning}
              >
                Start auto loop
              </Button>
              <Button
                danger
                loading={busyLoop}
                icon={<PauseCircleOutlined />}
                onClick={onStopLoop}
                disabled={!loopRunning && loop?.state !== 'stopping'}
              >
                Stop loop
              </Button>
              <Text type="secondary">Stop also kills the current download/scan right away.</Text>
              <Tag color={loop?.phase === 'scanning' ? 'cyan' : loop?.phase === 'downloading' ? 'blue' : 'default'}>
                phase: {loop?.phase || 'idle'}
              </Tag>
              <Text type="secondary">{loop?.message || 'Loop idle'}</Text>
            </Space>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={24}>
          <Card className="glass-card" title="Progress">
            <Progress
              percent={view.progress.percent}
              status={view.state === 'running' ? 'active' : view.progress.failed ? 'exception' : 'success'}
              strokeColor={{ from: '#06b6d4', to: '#38bdf8' }}
            />
            <Space wrap style={{ marginTop: 12 }}>
              <Tag icon={<SyncOutlined spin={view.state === 'running'} />}>
                {view.progress.completed}/{view.progress.total} done
              </Tag>
              <Tag color="success">{view.progress.succeeded} ok</Tag>
              <Tag color="error">{view.progress.failed} failed</Tag>
              <Tag>threads: {view.threads ?? '—'}</Tag>
              <Tag icon={<ApiOutlined />} color="orange">
                priority: {priorityLines.length}
              </Tag>
              <Tag icon={<ApiOutlined />}>other APIs: {otherLines.length}</Tag>
            </Space>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={24}>
          <Card
            className="glass-card"
            title={
              <Space>
                <SyncOutlined spin={activeApps.length > 0 && view.state === 'running'} />
                Apps in progress
                <Tag color="processing">{activeApps.length}</Tag>
              </Space>
            }
          >
            {activeApps.length ? (
              <Row gutter={[12, 12]}>
                {activeApps.map((app) => (
                  <Col xs={24} md={12} xl={8} key={app.apk}>
                    <div
                      style={{
                        border: '1px solid #1e293b',
                        borderRadius: 10,
                        padding: 12,
                        background: 'rgba(15, 23, 42, 0.55)',
                      }}
                    >
                      <Space style={{ width: '100%', justifyContent: 'space-between' }} wrap>
                        <Text code style={{ fontSize: 12 }}>
                          {app.apk}
                        </Text>
                        <Tag color={PHASE_COLOR[app.phase] || 'default'}>{app.phase}</Tag>
                      </Space>
                      <Progress
                        percent={Math.min(100, Number(app.percent) || 0)}
                        size="small"
                        status={app.phase === 'failed' ? 'exception' : 'active'}
                        strokeColor={PHASE_COLOR[app.phase] || '#818cf8'}
                        style={{ marginTop: 8, marginBottom: 4 }}
                      />
                      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                        <Text type="secondary" style={{ fontSize: 12 }}>
                          {app.message}
                        </Text>
                        <Text type="secondary" style={{ fontSize: 12, whiteSpace: 'nowrap' }}>
                          {((app.elapsed_ms || 0) / 1000).toFixed(1)}s
                        </Text>
                      </div>
                    </div>
                  </Col>
                ))}
              </Row>
            ) : (
              <Text type="secondary">
                {view.state === 'running' ? 'Waiting for the next APK worker…' : 'No apps scanning right now.'}
              </Text>
            )}
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={24} lg={12}>
          <Card
            className="glass-card"
            title={
              <Space>
                <SecurityScanOutlined /> Priority secrets
                <Tag color="orange">{priorityLines.length}</Tag>
              </Space>
            }
            extra={
              <Button icon={<DownloadOutlined />} onClick={onExportPriority}>
                Export TXT
              </Button>
            }
          >
            <Paragraph type="secondary" style={{ marginTop: 0 }}>
              Only AWS <Text code>Key:Secret</Text>, SendGrid (<Text code>SG.</Text>), and Stripe{' '}
              <Text code>sk_live_</Text>. Job “Secrets” can be higher when hits are Other-only.
            </Paragraph>
            <div style={monoBoxStyle}>
              {priorityLines.length ? priorityLines.join('\n') : <Text type="secondary">No AWS / SendGrid / sk_live hits yet.</Text>}
            </div>
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card
            className="glass-card"
            title={
              <Space>
                <ApiOutlined /> Other APIs
                <Tag>{otherLines.length}</Tag>
              </Space>
            }
            extra={
              <Button icon={<DownloadOutlined />} onClick={onExportOther}>
                Export TXT
              </Button>
            }
          >
            <Paragraph type="secondary" style={{ marginTop: 0 }}>
              Unique non-priority hits (newest first). Duplicate values across apps are only listed once.
            </Paragraph>
            <div style={monoBoxStyle}>
              {otherLines.length ? otherLines.join('\n') : <Text type="secondary">No other API secrets yet.</Text>}
            </div>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={14}>
          <Card
            className="glass-card"
            title="Recent jobs"
            extra={<Text type="secondary">P = Priority · O = Other APIs</Text>}
          >
            <Table
              size="small"
              rowKey={(r) => r.apk}
              pagination={{ pageSize: 8 }}
              dataSource={[...view.jobs].reverse()}
              columns={columns}
            />
          </Card>
        </Col>
        <Col xs={24} lg={10}>
          <Card className="glass-card" title="Logs" styles={{ body: { maxHeight: 420, overflow: 'auto', background: '#0f172a' } }}>
            <div style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: 12, lineHeight: 1.7 }}>
              {(view.logs || []).slice(-80).map((line, idx) => (
                <div
                  key={`${line.ts}-${idx}`}
                  style={{ color: line.level === 'error' ? '#fca5a5' : line.level === 'warning' ? '#fcd34d' : '#cbd5e1' }}
                >
                  <span style={{ color: '#64748b' }}>[{new Date(line.ts).toLocaleTimeString()}]</span>{' '}
                  <span style={{ color: line.level === 'error' ? '#f87171' : '#38bdf8' }}>{line.level.toUpperCase()}</span>{' '}
                  {line.message}
                </div>
              ))}
            </div>
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default DashboardPage;
