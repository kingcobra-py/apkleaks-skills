import React from 'react';
import { Typography, Row, Col, Card, Steps, Tabs, Tag, Button } from 'antd';
import {
  CloudDownloadOutlined,
  SettingOutlined,
  CheckCircleOutlined,
  CopyOutlined,
} from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { motion } from 'framer-motion';

const { Title, Paragraph, Text } = Typography;

const CodeBlock: React.FC<{ children: string }> = ({ children }) => {
  const [copied, setCopied] = React.useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(children);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div style={{ position: 'relative' }}>
      <pre className="code-block">{children}</pre>
      <Button
        type="text"
        size="small"
        icon={<CopyOutlined />}
        onClick={handleCopy}
        style={{ position: 'absolute', top: 8, right: 8, color: '#64748b' }}
      >
        {copied ? '✓' : ''}
      </Button>
    </div>
  );
};

const InstallPage: React.FC = () => {
  const { t } = useTranslation();

  const tabItems = [
    {
      key: 'uv',
      label: t('install.manual.uv'),
      children: (
        <CodeBlock>{`{
  "mcpServers": {
    "apkleaks": {
      "command": "uv",
      "args": ["run", "--directory", ".", "python3", "apkleaks-ai-cli.py", "mcp"]
    }
  }
}`}</CodeBlock>
      ),
    },
    {
      key: 'pipx',
      label: t('install.manual.pipx'),
      children: (
        <CodeBlock>{`{
  "mcpServers": {
    "apkleaks": {
      "command": "pipx",
      "args": ["run", "--directory", ".", "python3", "apkleaks-ai-cli.py", "mcp"]
    }
  }
}`}</CodeBlock>
      ),
    },
    {
      key: 'python',
      label: t('install.manual.python'),
      children: (
        <>
          <Paragraph type="secondary">{t('install.manual.pythonNote')}</Paragraph>
          <CodeBlock>{`{
  "mcpServers": {
    "apkleaks": {
      "command": "python3",
      "args": ["apkleaks-ai-cli.py", "mcp"]
    }
  }
}`}</CodeBlock>
        </>
      ),
    },
  ];

  return (
    <section className="section">
      <Title level={2} style={{ textAlign: 'center', marginBottom: 8 }}>
        {t('install.title')}
      </Title>
      <Paragraph style={{ textAlign: 'center', color: '#64748b', marginBottom: 48, maxWidth: 640, margin: '0 auto 48px' }}>
        {t('install.subtitle')}
      </Paragraph>

      {/* Prerequisites */}
      <motion.div initial={{ opacity: 0, y: 16 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}>
        <Card className="glass-card" style={{ marginBottom: 40 }}>
          <Title level={4}>{t('install.prereq')}</Title>
          <Row gutter={[12, 12]}>
            <Col><Tag color="blue">Python ≥ 3.8</Tag></Col>
            <Col><Tag color="blue">jadx v1.2.0</Tag> <Text type="secondary">(auto-downloaded)</Text></Col>
            <Col><Tag color="blue">pyaxmlparser ≥ 0.24</Tag> <Text type="secondary">(scan/info only)</Text></Col>
            <Col><Tag color="blue">uv</Tag> <Text type="secondary">(MCP deps)</Text></Col>
          </Row>
        </Card>
      </motion.div>

      {/* Plugin install */}
      <Title level={3}>{t('install.plugin.title')}</Title>
      <Paragraph type="secondary" style={{ marginBottom: 24 }}>
        {t('install.plugin.subtitle')}
      </Paragraph>
      <Steps
        direction="vertical"
        size="small"
        current={-1}
        items={[
          {
            title: t('install.plugin.step1'),
            icon: <CloudDownloadOutlined />,
            description: <CodeBlock>{'/plugin marketplace add android-security-engineer/apkleaks-skills'}</CodeBlock>,
          },
          {
            title: t('install.plugin.step2'),
            icon: <SettingOutlined />,
            description: <CodeBlock>{'/plugin install apkleaks'}</CodeBlock>,
          },
          {
            title: t('install.plugin.step3'),
            icon: <CheckCircleOutlined />,
            description: <CodeBlock>{'/rev-apkleaks scan app.apk\napkleaks_scan({ "file": "app.apk" })'}</CodeBlock>,
          },
        ]}
      />

      {/* Manual MCP */}
      <Title level={3} style={{ marginTop: 56 }}>{t('install.manual.title')}</Title>
      <Paragraph type="secondary" style={{ marginBottom: 16 }}>
        {t('install.manual.subtitle')}
      </Paragraph>
      <Tabs items={tabItems} />

      {/* CLI only */}
      <Title level={3} style={{ marginTop: 56 }}>{t('install.cli.title')}</Title>
      <Paragraph type="secondary">{t('install.cli.subtitle')}</Paragraph>
      <CodeBlock>{`python3 apkleaks-ai-cli.py schema                       # discover all capabilities
python3 apkleaks-ai-cli.py scan -f app.apk -s critical  # triage critical findings only
python3 apkleaks-ai-cli.py explain -c AWS_API_Key       # impact + remediation per category`}</CodeBlock>
    </section>
  );
};

export default InstallPage;
