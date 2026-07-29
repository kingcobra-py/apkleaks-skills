import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Badge,
  Button,
  Card,
  Col,
  InputNumber,
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
  aws_pairs?: string[];
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
  config?: { threads?: number; download_count?: number };
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
  jobs: Job[];
  logs: LogLine[];
  raw_lines?: string[];
  aws_pairs?: string[];
  system?: SystemStats;
  config?: { threads?: number; download_count?: number };
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
  current: ['org.example.app.apk'],
  jobs: [],
  logs: [{ ts: '2026-07-29T21:00:01+00:00', level: 'info', message: 'Discovered 100 APK(s); threads=4' }],
  raw_lines: [
    'AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    'example_payment_token_not_real',
  ],
  aws_pairs: ['AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'],
  system: {
    cpu_percent: 12.5,
    memory: { percent: 18.2, used_gb: 22.1, total_gb: 125 },
    apk_count: 99,
    download_running: false,
    scan_running: true,
    config: { threads: 4, download_count: 100 },
  },
};

const apiBaseCandidates = ['', 'http://127.0.0.1:8787'];

async function apiFetch(path: string, init?: RequestInit): Promise<Response | null> {
  for (const base of apiBaseCandidates) {
    try {
      const res = await fetch(`${base}${path}`, { cache: 'no-store', ...init });
      if (res.ok || res.status < 500) return res;
    } catch {
      // try next
    }
  }
  return null;
}

const DashboardPage: React.FC = () => {
  const [status, setStatus] = useState<Status>(DEMO);
  const [source, setSource] = useState<'demo' | 'live'>('demo');
  const [downloadCount, setDownloadCount] = useState<number>(100);
  const [threads, setThreads] = useState<number>(4);
  const [busyDownload, setBusyDownload] = useState(false);
  const [busyThreads, setBusyThreads] = useState(false);
  const [resultsLines, setResultsLines] = useState<string[]>([]);

  const refresh = useCallback(async () => {
    const res = await apiFetch('/api/status');
    if (!res || !res.ok) return;
    const data = (await res.json()) as Status;
    if (!data?.progress) return;
    setStatus(data);
    setSource(data.demo ? 'demo' : 'live');
    if (data.config?.download_count) setDownloadCount(data.config.download_count);
    if (data.config?.threads) setThreads(data.config.threads);
    else if (data.threads) setThreads(data.threads);

    const resultsRes = await apiFetch('/api/results');
    if (resultsRes?.ok) {
      const agg = await resultsRes.json();
      if (Array.isArray(agg?.lines)) setResultsLines(agg.lines);
    } else if (data.raw_lines) {
      setResultsLines(data.raw_lines);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      if (cancelled) return;
      await refresh();
    };
    tick();
    const id = window.setInterval(tick, 2500);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [refresh]);

  const onDownload = async () => {
    setBusyDownload(true);
    try {
      const res = await apiFetch('/api/download', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ count: downloadCount }),
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

  const onExportTxt = async () => {
    const res = await apiFetch('/api/results.txt');
    let text = resultsLines.join('\n');
    if (res?.ok) text = await res.text();
    const blob = new Blob([text.endsWith('\n') || !text ? text : `${text}\n`], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'apkleaks-results.txt';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const stateColor = status.state === 'completed' ? 'success' : status.state === 'running' ? 'processing' : 'default';
  const sys = status.system;
  const cpu = sys?.cpu_percent ?? 0;
  const mem = sys?.memory?.percent ?? 0;

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
        dataIndex: 'finding_count',
        key: 'finding_count',
        width: 90,
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
    <div style={{ padding: '32px 24px', maxWidth: 1200, margin: '0 auto' }}>
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
        <Space align="center" style={{ marginBottom: 8 }} wrap>
          <Title level={2} style={{ margin: 0 }}>
            Batch Scan Dashboard
          </Title>
          <Badge status={stateColor as 'success' | 'processing' | 'default'} text={status.state.toUpperCase()} />
          <Tag color={source === 'live' ? 'green' : 'gold'}>{source === 'live' ? 'LIVE' : 'DEMO'}</Tag>
          {sys?.download_running ? <Tag color="blue">DOWNLOADING</Tag> : null}
          {sys?.scan_running ? <Tag color="purple">SCANNING</Tag> : null}
        </Space>
        <Paragraph type="secondary" style={{ maxWidth: 760 }}>
          Download unique F-Droid APKs, control scan threads, watch CPU/RAM, and export raw secrets (AWS as{' '}
          <Text code>AwsKey:AwsSecretKey</Text>).
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

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={24} md={8}>
          <Card className="glass-card" title={<Space><CloudDownloadOutlined /> Download APKs</Space>}>
            <Space direction="vertical" style={{ width: '100%' }} size="middle">
              <div>
                <Text type="secondary">Number of new APKs (skips duplicates)</Text>
                <InputNumber
                  min={1}
                  max={5000}
                  value={downloadCount}
                  onChange={(v) => setDownloadCount(Number(v || 1))}
                  style={{ width: '100%', marginTop: 8 }}
                />
              </div>
              <Button type="primary" block loading={busyDownload} icon={<CloudDownloadOutlined />} onClick={onDownload}>
                Start download
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
              <Button type="primary" block loading={busyThreads} icon={<ThunderboltOutlined />} onClick={onApplyThreads}>
                Apply & restart scan
              </Button>
              <Text type="secondary">Active setting: {status.threads ?? threads}</Text>
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
                <Progress percent={Math.min(100, Number(mem) || 0)} strokeColor="#818cf8" />
              </div>
            </Space>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={24}>
          <Card className="glass-card" title="Progress">
            <Progress
              percent={status.progress.percent}
              status={status.state === 'running' ? 'active' : status.progress.failed ? 'exception' : 'success'}
              strokeColor={{ from: '#06b6d4', to: '#4f46e5' }}
            />
            <Space wrap style={{ marginTop: 12 }}>
              <Tag icon={<SyncOutlined spin={status.state === 'running'} />}>
                {status.progress.completed}/{status.progress.total} done
              </Tag>
              <Tag color="success">{status.progress.succeeded} ok</Tag>
              <Tag color="error">{status.progress.failed} failed</Tag>
              <Tag>threads: {status.threads ?? '—'}</Tag>
              <Tag icon={<ApiOutlined />}>secrets: {status.counts.findings}</Tag>
              <Tag color="orange">AWS pairs: {(status.aws_pairs || []).length}</Tag>
            </Space>
            {status.current?.length ? (
              <Paragraph style={{ marginTop: 16, marginBottom: 0 }}>
                <Text type="secondary">Currently scanning: </Text>
                {status.current.map((name) => (
                  <Tag key={name} color="processing">
                    {name}
                  </Tag>
                ))}
              </Paragraph>
            ) : null}
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={24}>
          <Card
            className="glass-card"
            title={
              <Space>
                <SecurityScanOutlined /> Results (raw)
                <Tag>{resultsLines.length}</Tag>
              </Space>
            }
            extra={
              <Button icon={<DownloadOutlined />} onClick={onExportTxt}>
                Export to TXT
              </Button>
            }
          >
            <Paragraph type="secondary" style={{ marginTop: 0 }}>
              AWS shown as <Text code>AwsKey:AwsSecretKey</Text>. Other hits are raw secret/API values only.
            </Paragraph>
            <div
              style={{
                fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
                fontSize: 12,
                lineHeight: 1.7,
                maxHeight: 320,
                overflow: 'auto',
                background: '#0f172a',
                color: '#e2e8f0',
                padding: 16,
                borderRadius: 8,
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
              }}
            >
              {resultsLines.length ? resultsLines.join('\n') : <Text type="secondary">No secrets found yet.</Text>}
            </div>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={14}>
          <Card className="glass-card" title="Recent jobs">
            <Table
              size="small"
              rowKey={(r) => r.apk}
              pagination={{ pageSize: 8 }}
              dataSource={[...status.jobs].reverse()}
              columns={columns}
            />
          </Card>
        </Col>
        <Col xs={24} lg={10}>
          <Card className="glass-card" title="Logs" styles={{ body: { maxHeight: 420, overflow: 'auto', background: '#0f172a' } }}>
            <div style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: 12, lineHeight: 1.7 }}>
              {(status.logs || []).slice(-80).map((line, idx) => (
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
