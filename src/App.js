import React, { Component } from 'react';
import './App.css';
import { Layout, Header, Navigation, Drawer, Content } from 'react-mdl';
import Main from './components/main';
import { Link } from 'react-router-dom';


class App extends Component {
  render() {
    return (
      <div>
        <Layout>
          <Header className="header-color" title={<Link style={{
            textDecoration: 'none',
            color: "white"
          }} to="/123"><strong>My Portfolio</strong></Link>} scroll>
            <Navigation >
              <Link to="/resume"><strong>Resume/Contect</strong></Link>
              <Link to="/aboutme"><strong>AboutMe</strong></Link>
              <Link to="/projects"><strong>Projects</strong></Link>
            </Navigation>
          </Header>
          <Drawer className="navi-grid" title={<Link style={{
            textDecoration: 'none',
            color: "black"
          }} to="/123"><strong>My Portfolio</strong></Link>}>
            <Navigation>
              <Link to="/resume" style={{color:"black"}}><strong>Resume/Contect</strong></Link>
              <Link to="/aboutme" style={{color:"black"}}><strong>AboutMe</strong></Link>
              <Link to="/projects" style={{color:"black"}}><strong>Projects</strong></Link>
            </Navigation>
          </Drawer>
          <Content className="navi-grid">
            <div className="page-content" />
            <Main />
          </Content>
        </Layout>
      </div>
    );
  }
}
export default App;