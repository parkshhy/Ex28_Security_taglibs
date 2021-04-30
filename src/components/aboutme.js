import React, { Component } from 'react';
import { Grid, Cell } from 'react-mdl';
import Skills from './skills'


class Aboutme extends Component {
    render() {
        return (
            <div>
                <Grid >
                    <Cell style={{}} className="resume-right-col" col={4}>
                    <h2>Certificate</h2>
                    <h4>・ JLPT  N2</h4>
                    <h4>・ 情報処理産業技師（基本情報技術者）</h4>
                    <h4>・ 大韓航空予約プログラム TOPAS</h4>
                    <h4>・ 運転免許証</h4>
                    </Cell>

                    <Cell className="resume-right-col" col={8}>
                  <h2>Skills</h2>
                  
                    <h5>Frontend</h5>
                   <Skills
                   skills="💻JavaScript"
                   progress={70} buffer={30}
                   />
                    <Skills
                   skills="💻Node JS"
                   progress={60} buffer={40}
                   />
                   <Skills
                   skills="💻HTML"
                   progress={70}  buffer={30}
                   />
                 
                  <Skills 
                   skills="💻CSS"
                   progress={70} buffer={37}
                   />
                   <hr style={{ borderTop: '3px solid #395181' }}></hr>
                   <h5>Backend</h5>
                    <Skills
                   skills="⌨️JAVA"
                   progress={60} buffer={40}
                   />
                   <hr style={{ borderTop: '3px solid #395181' }}></hr>
                    <h5>FW</h5>
                    <Skills
                   skills="⚒️SPRING Boot"
                   progress={50} buffer={40}
                   />
                    <Skills
                   skills="⚒️React"
                   progress={60} buffer={40}
                   />
                    <Skills
                   skills="⚒️React Native"
                   progress={60} buffer={40}
                   />
                   <hr style={{ borderTop: '3px solid #395181' }}></hr>
                   <h5>DB</h5>
                   <Skills
                   skills="📊Oracle"
                   progress={65}
                   />
                    <Skills
                   skills="📊MySql"
                   progress={65}
                   />
                    <Skills
                   skills="📊MariaDB"
                   progress={65}
                   /> 
                   <hr style={{ borderTop: '3px solid #395181' }}></hr>

                   <h5>Language</h5>
                   <Skills
                   skills="🇰🇷Korean"
                   progress={100}
                   />
                   <Skills
                   skills="🇯🇵Japanese"
                   progress={90} buffer={10}
                   />
                   <Skills
                   skills="🇺🇸English"
                   progress={55} buffer={45}
                   />
                   <hr style={{ borderTop: '3px solid #395181' }}></hr>     

 </Cell>
                </Grid>
            </div>
        )
    }
}
export default Aboutme;
