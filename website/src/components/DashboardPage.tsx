import React, { useEffect, useMemo, useState } from 'react';
import { Badge, Card, Col, Progress, Row, Space, Table, Tag, Typography, Alert } from 'antd';
import {
  CloudDownloadOutlined,
  ThunderboltOutlined,
  SecurityScanOutlined,
  ApiOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  SyncOutlined,
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
  counts: { findings: 128, critical: 11, high: 37, has_aws: 3, has_sendgrid: 1, has_stripe: 2 },
  current: ['org.example.app.apk', 'com.demo.wallet.apk'],
  jobs: [
    {
      apk: 'org.fdroid.fdroid.apk',
      ok: true,
      finding_count: 2,
      has_critical: false,
      duration_ms: 51200,
      hits: { aws: false, sendgrid: false, stripe: false },
    },
    {
      apk: 'com.demo.payments.apk',
      ok: true,
      finding_count: 5,
      has_critical: true,
      duration_ms: 78410,
      hits: { aws: true, sendgrid: false, stripe: true },
    },
    {
      apk: 'broken.sample.apk',
      ok: false,
      finding_count: 0,
      has_critical: false,
      duration_ms: 1200,
      error: 'INVALID_APK',
      hits: { aws: false, sendgrid: false, stripe: false },
    },
  ],
  logs: [
    { ts: '2026-07-29T21:00:01+00:00', level: 'info', message: 'Discovered 100 APK(s); threads=4' },
    { ts: '2026-07-29T21:05:12+00:00', level: 'info', message: 'Done org.fdroid.fdroid.apk: findings=2 ok=True (51200 ms)' },
    { ts: '2026-07-29T21:08:44+00:00', level: 'info', message: 'Done com.demo.payments.apk: findings=5 ok=True (78410 ms)' },
    { ts: '2026-07-29T21:10:02+00:00', level: 'error', message: 'Done broken.sample.apk: findings=0 ok=False (1200 ms)' },
    { ts: '2026-07-29T21:12:10+00:00', level: 'info', message: 'Scanning org.example.app.apk' },
  ],
};

const statusEndpoints = [
  'http://127.0.0.1:8787/api/status',
  '/api/status',
];

const DashboardPage: React.FC = () => {
  const [status, setStatus] = useState<Status>(DEMO);
  const [source, setSource] = useState<'demo' | 'live'>('demo');

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      for (const url of statusEndpoints) {
        try {
          const res = await fetch(url, { cache: 'no-store' });
          if (!res.ok) continue;
          const data = (await res.json()) as Status;
          if (cancelled || !data?.progress) continue;
          setStatus(data);
          setSource(data.demo ? 'demo' : 'live');
          return;
        } catch {
          // try next endpoint
        }
      }
    };
    tick();
    const id = window.setInterval(tick, 2500);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  const stateColor = status.state === 'completed' ? 'success' : status.state === 'running' ? 'processing' : 'default';

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
        title: 'Findings',
        dataIndex: 'finding_count',
        key: 'finding_count',
        render: (n: number, row: Job) => (
          <Space>
            <Text>{n ?? 0}</Text>
            {row.has_critical ? <Tag color="magenta">critical</Tag> : null}
          </Space>
        ),
      },
      {
        title: 'Hits',
        key: 'hits',
        render: (_: unknown, row: Job) => (
          <Space wrap>
            {row.hits?.aws ? <Tag color="orange">AWS</Tag> : null}
            {row.hits?.sendgrid ? <Tag color="blue">SendGrid</Tag> : null}
            {row.hits?.stripe ? <Tag color="purple">Stripe</Tag> : null}
            {!row.hits?.aws && !row.hits?.sendgrid && !row.hits?.stripe ? <Text type="secondary">—</Text> : null}
          </Space>
        ),
      },
      {
        title: 'Duration',
        dataIndex: 'duration_ms',
        key: 'duration_ms',
        render: (ms?: number) => (ms != null ? `${(ms / 1000).toFixed(1)}s` : '—'),
      },
    ],
    [],
  );

  return (
    <div style={{ padding: '48px 24px', maxWidth: 1200, margin: '0 auto' }}>
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
        <Space align="center" style={{ marginBottom: 8 }}>
          <Title level={2} style={{ margin: 0 }}>
            Batch Scan Dashboard
          </Title>
          <Badge status={stateColor as 'success' | 'processing' | 'default'} text={status.state.toUpperCase()} />
          <Tag color={source === 'live' ? 'green' : 'gold'}>{source === 'live' ? 'LIVE' : 'DEMO'}</Tag>
        </Space>
        <Paragraph type="secondary" style={{ maxWidth: 720 }}>
          Download APKs from F-Droid, scan many files in parallel, and watch progress, logs, and AWS / SendGrid / Stripe hits in one place.
        </Paragraph>
      </motion.div>

      {source === 'demo' && (
        <Alert
          style={{ marginBottom: 20 }}
          type="info"
          showIcon
          message="Showing demo data"
          description={
            <span>
              Start the API with <Text code>python3 tools/dashboard_server.py</Text> after a batch scan writes{' '}
              <Text code>results/status.json</Text>.
            </span>
          }
        />
      )}

      <Row gutter={[16, 16]} style={{ marginBottom: 20 }}>
        <Col xs={24} md={16}>
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
        <Col xs={24} md={8}>
          <Card className="glass-card" title="How to run">
            <Paragraph style={{ marginBottom: 8 }}>
              <CloudDownloadOutlined /> <Text code>python3 tools/fdroid_download.py -n 100 -o apks</Text>
            </Paragraph>
            <Paragraph style={{ marginBottom: 8 }}>
              <ThunderboltOutlined /> <Text code>python3 tools/batch_scan.py -d apks -t 4 -o results</Text>
            </Paragraph>
            <Paragraph style={{ marginBottom: 0 }}>
              <SecurityScanOutlined /> <Text code>python3 tools/dashboard_server.py</Text>
            </Paragraph>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 20 }}>
        {[
          { title: 'Findings', value: status.counts.findings, icon: <SecurityScanOutlined />, color: '#0f172a' },
          { title: 'Critical', value: status.counts.critical, icon: <CloseCircleOutlined />, color: '#ef4444' },
          { title: 'AWS hits', value: status.counts.has_aws, icon: <ApiOutlined />, color: '#f59e0b' },
          { title: 'SendGrid', value: status.counts.has_sendgrid, icon: <ApiOutlined />, color: '#06b6d4' },
          { title: 'Stripe', value: status.counts.has_stripe, icon: <ApiOutlined />, color: '#8b5cf6' },
          { title: 'High', value: status.counts.high, icon: <CheckCircleOutlined />, color: '#10b981' },
        ].map((item) => (
          <Col xs={12} md={4} key={item.title}>
            <Card className="glass-card" styles={{ body: { padding: 16 } }}>
              <Space direction="vertical" size={0}>
                <Text type="secondary">
                  {item.icon} {item.title}
                </Text>
                <Title level={3} style={{ margin: 0, color: item.color }}>
                  {item.value}
                </Title>
              </Space>
            </Card>
          </Col>
        ))}
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
                <div key={`${line.ts}-${idx}`} style={{ color: line.level === 'error' ? '#fca5a5' : line.level === 'warning' ? '#fcd34d' : '#cbd5e1' }}>
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
