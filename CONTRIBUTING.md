# 🤝 Contributing to ThreatLens

Thank you for your interest in contributing to ThreatLens! This document provides guidelines and information for contributors.

---

## 🚀 Getting Started

### Prerequisites

- **Node.js 18+** installed
- **Git** configured with your name and email
- **VirusTotal API key** (for testing)
- **Code editor** with TypeScript support recommended

### Setup Development Environment

1. **Fork the Repository**
   ```bash
   # Fork on GitHub, then clone your fork
   git clone https://github.com/your-username/threatlens.git
   cd threatlens
   ```

2. **Install Dependencies**
   ```bash
   npm install
   ```

3. **Set Up Environment**
   ```bash
   cp .env.example .env.local
   # Add your VirusTotal API key to .env.local
   ```

4. **Start Development Server**
   ```bash
   npm run dev
   ```

5. **Verify Setup**
   - Open http://localhost:9002
   - Test a basic scan to ensure everything works

---

## 📋 Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### 2. Make Changes

- Follow the existing code style
- Add TypeScript types for new functionality
- Include comments for complex logic
- Update relevant documentation

### 3. Test Your Changes

```bash
# Type checking
npm run typecheck

# Build test
npm run build

# Manual testing
npm run dev
```

### 4. Commit Your Changes

```bash
git add .
git commit -m "feat: add new vulnerability detection type"
```

#### Commit Message Guidelines

Use conventional commits:

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `style:` Code style changes (formatting, etc.)
- `refactor:` Code refactoring
- `test:` Adding or updating tests
- `chore:` Maintenance tasks

Examples:
```bash
git commit -m "feat: add SSRF vulnerability detection"
git commit -m "fix: resolve API key validation issue"
git commit -m "docs: update README with new features"
```

### 5. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub with:
- Clear title and description
- Reference any related issues
- Include screenshots for UI changes
- Describe how to test your changes

---

## 🏗️ Code Style Guidelines

### TypeScript

- **Strict Mode**: Always use proper typing
- **Interfaces**: Define interfaces for complex objects
- **Enums**: Use enums for fixed sets of values
- **Imports**: Keep imports organized and clean

```typescript
// ✅ Good
interface Vulnerability {
  type: string;
  severity: 'High' | 'Medium' | 'Low';
  description: string;
}

// ❌ Bad
interface Vulnerability {
  type: any;
  severity: any;
  description: any;
}
```

### React Components

- **Functional Components**: Use hooks and functional components
- **Props Interface**: Define props with TypeScript interfaces
- **Default Exports**: Use default exports for components
- **JSX Consistency**: Follow existing patterns

```typescript
// ✅ Good
interface ScanFormProps {
  onSubmit: (data: ScanData) => void;
  isLoading: boolean;
}

export function ScanForm({ onSubmit, isLoading }: ScanFormProps) {
  // Component logic
}
```

### File Organization

- **Components**: Keep components in appropriate directories
- **Utils**: Place utility functions in `src/lib/utils.ts`
- **Types**: Define shared types in `src/lib/types.ts`
- **Constants**: Use constants for magic numbers and strings

---

## 🔍 Adding New Features

### Vulnerability Detection

To add a new vulnerability detection type:

1. **Update Scanner Logic** (`src/lib/scanner.ts`):
   ```typescript
   private analyzeNewVulnerability(url: string): Vulnerability | null {
     // Your detection logic here
     return {
       type: 'New Vulnerability',
       severity: 'Medium',
       description: 'Description of the vulnerability',
       potentialImpact: 'Impact description',
       remediation: 'How to fix it'
     };
   }
   ```

2. **Add to Main Analysis**:
   ```typescript
   const vulnerabilities = [
     ...this.analyzeCommonVulnerabilities(url),
     ...this.analyzeNewVulnerability(url), // Add here
     ...this.generateSecurityRecommendations(url, null)
   ];
   ```

3. **Update Types** (if new severity levels needed):
   ```typescript
   export interface Vulnerability {
     type: string;
     severity: 'High' | 'Medium' | 'Low'; // Add new levels if needed
     description: string;
     potentialImpact: string;
     remediation: string;
   }
   ```

### UI Components

When adding new UI components:

1. **Follow Radix UI Patterns**: Use existing UI components as patterns
2. **Responsive Design**: Ensure components work on mobile and desktop
3. **Accessibility**: Include proper ARIA labels and semantic HTML
4. **Loading States**: Add loading indicators for async operations

### API Integration

When adding new API integrations:

1. **Error Handling**: Always include proper error handling
2. **Type Safety**: Define interfaces for API responses
3. **Rate Limiting**: Consider API rate limits
4. **Security**: Never expose API keys to client-side code

---

## 🧪 Testing

### Manual Testing Checklist

Before submitting a PR, test:

- [ ] Basic URL scanning works
- [ ] Error handling displays correctly
- [ ] UI looks good on different screen sizes
- [ ] Reports generate and download correctly
- [ ] Environment variables work properly

### Testing Scenarios

Test with various URL types:
- **HTTPS sites**: `https://google.com`
- **HTTP sites**: `http://example.com`
- **URLs with parameters**: `https://example.com?id=123`
- **Invalid URLs**: Test error handling
- **Malicious URLs**: If available for testing

---

## 📖 Documentation

When contributing:

1. **Update README.md**: If adding major features
2. **Update Docs**: Add relevant documentation in `/docs`
3. **Code Comments**: Comment complex logic
4. **Type Definitions**: Ensure all interfaces are documented

### Documentation Style

- **Clear Headings**: Use markdown headers appropriately
- **Code Examples**: Include working code examples
- **Screenshots**: Add screenshots for UI changes
- **Links**: Cross-reference related sections

---

## 🐛 Bug Reports

When reporting bugs:

1. **Use Issue Template**: Follow the GitHub issue template
2. **Include Environment**: Node version, OS, browser
3. **Provide Steps**: Clear steps to reproduce
4. **Add Context**: What you expected vs. what happened
5. **Include Logs**: Relevant error messages or console output

---

## 💡 Feature Requests

When requesting features:

1. **Use Cases**: Describe the problem you're trying to solve
2. **Proposed Solution**: How you envision the feature working
3. **Alternatives**: Any alternative solutions you considered
4. **Priority**: How important this feature is to you

---

## 🎯 Areas for Contribution

We welcome contributions in these areas:

### High Priority
- **New Vulnerability Types**: Additional detection patterns
- **UI Improvements**: Better user experience and accessibility
- **Performance**: Optimization and speed improvements
- **Error Handling**: Better error messages and recovery

### Medium Priority
- **Documentation**: Improving docs and examples
- **Testing**: Adding automated tests
- **Internationalization**: Multiple language support
- **Themes**: Dark/light mode themes

### Low Priority
- **Analytics**: Usage statistics and tracking
- **Export Formats**: PDF, JSON export options
- **API Extensions**: Additional security APIs integration

---

## 🤝 Community Guidelines

### Code of Conduct

- **Respect**: Be respectful and inclusive
- **Constructive**: Provide constructive feedback
- **Helpful**: Help others learn and grow
- **Patient**: Be patient with questions and issues

### Getting Help

- **Discussions**: Use GitHub Discussions for questions
- **Issues**: Use GitHub Issues for bug reports and features
- **Documentation**: Check docs before asking questions
- **Search**: Look for existing issues before creating new ones

---

## 🏆 Recognition

Contributors will be recognized in:

- **README.md**: Contributors section
- **Release Notes**: Mentioned in relevant releases
- **Community**: Highlighted in discussions and announcements

---

## 📜 License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

---

## 🙏 Thank You

Thank you for contributing to ThreatLens! Your contributions help make web security more accessible to everyone.

If you have any questions or need help getting started, please don't hesitate to reach out in our [Discussions](https://github.com/your-repo/threatlens/discussions).