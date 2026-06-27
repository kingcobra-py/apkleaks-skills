import React from 'react';
import { Typography, Row, Col, Card, Steps, Tabs, Tag } from 'antd';
import {
  CloudDownloadOutlined,
  SettingOutlined,
  CheckCircleOutlined,
} from '@ant-design/icons';

const { Title, Paragraph, Text } = Typography;

const codeStyle: React.CSSProperties = {
  background: '#0f172a',
  color: '#e2e8f0',
  padding: '16px 20px',
  borderRadius: 8,
  fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
  fontSize: '0.85rem',
  lineHeight: 1.6,
  overflowX: 'auto',
  whiteSpace: 'pre',
};

const InstallPage: React.FC = () => (
  <section className="section">
    <Title level={2} style={{ textAlign: 'center', marginBottom: 8 }}>
      Install — Plug It Into Your Agent
    </Title>
    <Paragraph style={{ textAlign: 'center', color: '#64748b', marginBottom: 48 }}>
      Not "install then run manually" — this wires the tool into your agent&apos;s runtime.
    </Paragraph>

    {/* Prerequisites */}
    <Card style={{ marginBottom: 40 }}>
      <Title level={4}>Prerequisites</Title>
      <Row gutter={[16, 12]}>
        <Col xs={24} sm={12}>
          <Tag color="blue">Python ≥ 3.8</Tag>
        </Col>
        <Col xs={24} sm={12}>
          <Tag color="blue">jadx v1.2.0</Tag> <Text type="secondary">(auto-downloaded on first decompile)</Text>
        </Col>
        <Col xs={24} sm={12}>
          <Tag color="blue">pyaxmlparser ≥ 0.24</Tag> <Text type="secondary">(scan/info/decompile only)</Text>
        </Col>
        <Col xs={24} sm={12}>
          <Tag color="blue">uv</Tag> <Text type="secondary">(MCP server auto-installs deps)</Text>
        </Col>
      </Row>
    </Card>

    {/* Recommended: Plugin install */}
    <Title level={3}>Recommended: Claude Code Plugin</Title>
    <Paragraph type="secondary" style={{ marginBottom: 24 }}>
      One step registers all 9 skills + the MCP server. No manual settings.json editing.
    </Paragraph>
    <Steps
      direction="vertical"
      size="small"
      current={-1}
      items={[
        {
          title: 'Add from marketplace',
          icon: <CloudDownloadOutlined />,
          description: (
            <div style={codeStyle}>/plugin marketplace add android-security-engineer/apkleaks-skills</div>
          ),
        },
        {
          title: 'Install the plugin',
          icon: <SettingOutlined />,
          description: <div style={codeStyle}>/plugin install apkleaks</div>,
        },
        {
          title: 'Done — use it',
          icon: <CheckCircleOutlined />,
          description: (
            <div>
              <div style={codeStyle}>{'/rev-apkleaks scan app.apk\n# or via MCP tool:\napkleaks_scan({ "file": "app.apk" })'}</div>
            </div>
          ),
        },
      ]}
    />

    {/* Manual MCP wiring */}
    <Title level={3} style={{ marginTop: 48 }}>Alternative: Manual MCP Server</Title>
    <Paragraph type="secondary" style={{ marginBottom: 24 }}>
      For local development on this repo, or non-plugin runtimes.
    </Paragraph>
    <Tabs
      items={[
        {
          key: 'uv',
          label: 'uv run (recommended)',
          children: (
            <div style={codeStyle}>{`{
  "mcpServers": {
    "apkleaks": {
      "command": "uv",
      "args": ["run", "--directory", ".", "python3", "apkleaks-ai-cli.py", "mcp"]
    }
  }
}`}</div>
          ),
        },
        {
          key: 'pipx',
          label: 'pipx run',
          children: (
            <div style={codeStyle}>{`{
  "mcpServers": {
    "apkleaks": {
      "command": "pipx",
      "args": ["run", "--directory", ".", "python3", "apkleaks-ai-cli.py", "mcp"]
    }
  }
}`}</div>
          ),
        },
        {
          key: 'python3',
          label: 'python3 (manual)',
          children: (
            <>
              <Paragraph type="secondary">Requires <Text code>pip install -e .</Text> first.</Paragraph>
              <div style={codeStyle}>{`{
  "mcpServers": {
    "apkleaks": {
      "command": "python3",
      "args": ["apkleaks-ai-cli.py", "mcp"]
    }
  }
}`}</div>
            </>
          ),
        },
      ]}
    />

    {/* CLI-only */}
    <Title level={3} style={{ marginTop: 48 }}>CLI Only — No Setup Required</Title>
    <Paragraph type="secondary">
      For any agent with Bash access, just run the CLI directly. Zero config.
    </Paragraph>
    <div style={codeStyle}>{`python3 apkleaks-ai-cli.py schema                       # discover all capabilities
python3 apkleaks-ai-cli.py scan -f app.apk -s critical  # triage critical findings only
python3 apkleaks-ai-cli.py explain -c AWS_API_Key       # impact + remediation per category`}</div>
  </section>
);

export default InstallPage;
